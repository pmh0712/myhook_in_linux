#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include "myutil.h"
#define TARGET_CALL_OFFSET 0 //우회할 함수 호출 위치 오프셋, 모든 부분에서 우회할 꺼면 0으로 변경 

//프로그램의 base
long program_base;
//라이브러리 base
long libc_base;
// 분석을 통해 알아낸 시그니처대로 타겟 전용 타입 정의
typedef void (*target_func_t)(void);
// 원본 함수를 저장할 함수 포인터
target_func_t original_function;
//트램펄린 코드 주소
void *trampoline_addr;
//14바이트 점프 명령어 템플릿
const unsigned char JMP_TEMPLATE[14] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  //JMP QWORD PTR [RIP+0] (현재 명령어 바로 뒤에 있는 8바이트 값을 읽어서 거기로 점프해라)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 우리가 직접 채워 넣을 8바이트 절대 주소 공간
};

void unprotect_memory(long target_addr)
{
    //1. 시스템의 페이지 크기 구하기(보통 4096=0x1000)
    long page_size =  sysconf(_SC_PAGE_SIZE);

    //2. 타겟 주소에서 나머지 값을 빼서 4096의 배수로 깎아버린 (페이지 시작주소 구하기)
    long page_start = target_addr & ~(page_size - 1);

    //3. mprotect 호출: 페이지 시작 주소부터 4096바이크 만큼 읽기/쓰기/실행 권한 부여
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1){
        perror("mprotect failed");
        _exit(1);
    }
}

void protect_memory(long target_addr)
{
    long page_size =  sysconf(_SC_PAGE_SIZE);
    long page_start = target_addr & ~(page_size - 1);

    // 쓰기 권한 해제
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC) == -1){
        perror("mprotect failed");
        _exit(1);
    }
}

bool is_rip_relative(cs_insn *insn){
    //rip 상대주소를 사용하는가 검사
    cs_x86 *x86 = &(insn->detail->x86);
    for(int i = 0; i < x86->op_count; i++){
        cs_x86_op *op = (&x86->operands[i]);

        //메모리 참조 피연산자이면서, 베이스 레지스터가 RIP인 경우
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP){
            return true;
        }
    }
    return false;
}


// dlsym이 반환해주는 strcmp 주소는 IFUNC(Indirect Function)로 인해
// CPU 하드웨어 지원 설정에 따라 런타임에 동적으로 결정되는 실제 함수의 진입점이므로,
// 이 주소를 기준으로 처음 몇 바이트의 명령어를 백업한 뒤 JMP 코드를 덮어씌워
// 안정적인 인라인 트램펄린(우회로)을 동적으로 생성 및 패치해야 한다.
// 특히 백업할 명령어 중에 RIP 상대 주소(PC-relative)를 사용하는 명령어가 포함되어 있으면
// 트램펄린이 할당된 메모리 위치에 맞춰 오프셋을 재계산해야 오류를 방지할 수 있다.
bool build_trampoline()
{
    //capstone 변수 세팅
    csh handle;   //capstone 세션핸들
    cs_insn *insn;//어셈블리 명령어를 담는 구조체
    size_t count; //명령어 개수

    // x86_64모드로 캡스톤 초기화
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        printf("capstone initializing fail!!\n");
        return false;
    }

    // 디스어셈블 전에 상세 옵션을 켜기 -> 상대주소 사용 유무 구별 
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // 훅을 걸기위해 14바이트 이상 명령어를 덮어써야함
    // 널널하게 32바이트 정도 디스어셈블
    count = cs_disasm(handle, (const uint8_t*)original_function, 32, (uint64_t)original_function, 0, &insn);

    if (count == 0){
        printf("disasmble failed!!\n");
        return false;
    }

    //2GB 이내 거리에 트램펄린을 저장하기 위한 hint address(함수위치 + 16MB)
    void* hint_address = (void*)((long)original_function +0x1000000);
    printf("hint_address: %lx\n", (long)hint_address);

    // mmap으로 트램펄린 공간 할당
    trampoline_addr = mmap(hint_address, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (trampoline_addr == MAP_FAILED) {
        perror("mmap failed");
        return false;
    }
    long distance = (long)trampoline_addr - (long)original_function;
    if(distance < -0x7FFFFFFF || distance > 0x7FFFFFFF){
        return false;
    }

    size_t accumulated_size = 0;
    uint8_t trampoline_buf[128];
    int trampoline_offset = 0;

    // 최소 14바이트가 넘을 때까지 원본 명령어를 몇 개 뜯어올지 계산
    for (size_t i = 0; i < count; i++){
        // 명령어 복사
        memcpy(&trampoline_buf[trampoline_offset], insn[i].bytes,insn[i].size);
        if(is_rip_relative(&insn[i])){
            cs_x86 *x86 =  &(insn[i].detail->x86);

            //기존 명령어 오프셋 값(disp)
            int32_t orig_disp = x86->disp;

            //원래 명령어가 가르키면 절대 주소
            uint64_t orig_abs_addr = insn[i].address+insn[i].size+orig_disp;
            //트램펄린의 현재 명령어 절대주소
            uint64_t tram_abs_addr = (long)trampoline_addr + trampoline_offset;
            
            //트램펄린 기준 오프셋 재계산
            //새 오프셋 = 원래 절대주소 - (현태 트램펄린 명령어 주소 + 현재 명령어 길이)
            int32_t new_disp = (uint32_t)(orig_abs_addr-(tram_abs_addr+insn[i].size));
            
            //복사해둔 명령어 오프셋 위치를 새로구한 오프셋으로 변경
            //캡스톤이 알려주는 오프셋 위치(disp_offset)을 활용
            uint8_t disp_offset = x86->encoding.disp_offset;
            *(int32_t*)(&trampoline_buf[trampoline_offset + disp_offset]) = new_disp;

            printf("[%ld] instructor changed!\n", i);
            printf("abs_addr = %lx\n", orig_abs_addr);
            printf("new offset: %x, trampoline cur addr: %lx\n", new_disp, tram_abs_addr);
            printf("check new offset + trampoline cur addr = %lx\n", new_disp + tram_abs_addr + insn[i].size);
        }
        accumulated_size += insn[i].size;
        trampoline_offset += insn[i].size;

        if (accumulated_size >= 14) break;
    }

    if (accumulated_size < 14){
        printf("this function is too short!! (function length < 14bytes)\n");
        cs_free(insn, count);
        cs_close(&handle);
        return false;
    }

    //임시 버퍼에 있던 값 전달
    memcpy(trampoline_addr, trampoline_buf, trampoline_offset);


    //트램펄린으로 점프하기위한 점프 명령어 세팅
    unsigned char jmp_trampoline[14];
    memcpy(jmp_trampoline, JMP_TEMPLATE, 14);

    // 돌아갈 주소 계산 및 JMP 조립 (64비트 절대주소 점프)
    long return_addr = (long)original_function + accumulated_size;
    *(long*)(&jmp_trampoline[6]) = return_addr;

    // 복사한 14바이트 바로 뒤에 JMP 기계어 이어 붙이기
    memcpy((void*)((long)trampoline_addr + trampoline_offset), jmp_trampoline, 14);
    return true;
}

//우리가 실행시킬 훅 함수 이것도 타겟 함수에 맞춰 다시 만들어줘야한다
void myfunction(void)
{
    printf("HOOKED!!!!\n");
    target_func_t return_original= (target_func_t)trampoline_addr; 
    return return_original();
}

void setup_hook() {
    //먼저 디버거를 이용한 분석을 통해 target의 오프셋을 획득
    long target_offset = 0x1189;

    //프로그램, 라이브러리의 base를 획득
    pid_t mypid = getpid();
    printf("get pid %d\n", mypid);
    program_base = get_base_sys(mypid, NULL);
    libc_base = get_base_sys(mypid, "libc.so.6");
    original_function =  (target_func_t)(program_base + target_offset);
    printf("[*] program_base: 0x%lx, libc_base: 0x%lx, target_address: 0x%lx\n", program_base, libc_base, (long)original_function);


    //쓰기 권한 변경
    unprotect_memory((long)original_function);
    //트램펄린 생성
    if(!build_trampoline()){
        printf("build trampoline fail!!\n");
        return;
    }
    //변경할 훅 함수 주소
    long myfunction_addr = (long)myfunction;
    //64비트 환경에서 점프를 위한 점프 명령어 세팅
    unsigned char jmp_hook[14];
    memcpy(jmp_hook, JMP_TEMPLATE, 14);

    //6번 인덱스에 훅 함수의 주소를 저장
    *(long*)(&jmp_hook[6]) = myfunction_addr;
    //mprotect로 쓰기 권한을 얻은 공간에 overwrite
    memcpy((void*)original_function, jmp_hook, 14);
    //쓰기권한 해제
    protect_memory((long)original_function);

    printf("[+] HOOK SETUP DONE!\n");
}

//라이브러리가 dlopne으로 로드되자 마자 '자동으로' 실행되는 초기화 함수
__attribute__((constructor))
void on_library_loaded(){
    // 밖에서 dlopne이 성공하는 즉시 이 코드가 자동으로 실행됨
    setup_hook();
}