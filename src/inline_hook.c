#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
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


/**
 * @brief 인라인 훅(Inline Hook)을 위한 트램펄린 동적 생성 및 명령어 릴로케이션
 * 
 * 타겟 함수의 프롤로그(최소 14바이트)를 디코딩하여 트램펄린 버퍼로 복사한다.
 * 복사 과정에서 다음의 주소 보정(Relocation) 작업을 수행한다:
 *   1. RIP 상대 참조(Data): 트램펄린 위치에 맞춰 변위(Disp) 재계산
 *   2. 상대 분기문(Branch): 도착지 절대 주소 보존 및 변위 재계산
 *   3. Short 분기문: 오프셋 범위 확장(Expansion)을 위해 Near 분기문(5~6바이트)으로 뻥튀기 후 패치
 * 
 * @return 훅 생성 성공 여부 (true/false)
 */
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
    void* hint_address = (void*)((long)original_function + 0x1000000);
    printf("hint_address: %lx\n", (long)hint_address);

    // mmap으로 트램펄린 공간 할당
    trampoline_addr = mmap(hint_address, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (trampoline_addr == MAP_FAILED) {
        perror("mmap failed");
        return false;
    }

    //2GB 바깥에 트램펄린이 생성 시 훅 생성 실패
    long distance = (long)trampoline_addr - (long)original_function;
    if(distance < INT32_MIN || distance > INT32_MAX){
        return false;
    }

    size_t accumulated_size = 0;
    uint8_t trampoline_buf[128];
    int trampoline_offset = 0;

    // 최소 14바이트가 넘을 때까지 원본 명령어를 몇 개 뜯어올지 계산
    for (size_t i = 0; i < count; i++){
        // 명령어 복사
        memcpy(&trampoline_buf[trampoline_offset], insn[i].bytes, insn[i].size);
        //트램펄린의 현재 명령어 절대주소
        uint64_t tram_abs_addr = (long)trampoline_addr + trampoline_offset;
        //원래 주소가 가르키던 주소를 담을 저장공간
        uint64_t orig_abs_addr = 0;
        // 새로 갱신할 offset
        int64_t new_offset = 0;
        //명령어에 대한 정보
        cs_x86 *x86 =  &(insn[i].detail->x86);

        //원래 주소가 가르키던 곳(orig_abs_addr) 구하기
        //rip 레지스터 상대주소 지정(rip + offset)을 쓰는 명령어들
        if(is_rip_relative(&insn[i])){
            // MOV, LEA 같은 데이터 참조문은 disp를 더해서 직접 계산해야 함, capstone이 미리 만들어 주지 않음
            orig_abs_addr = insn[i].address + insn[i].size + x86->disp;
        }

        // 직접 상대 분기문, 메모리 데이터 참조가 아닌 명령어 자체의 변위 사용 
        else if(insn[i].bytes[0] == 0xE8 || //Direct CALL
                insn[i].bytes[0] == 0xE9 || // Near JMP
                insn[i].bytes[0] == 0xEB || // Short JMP
                (insn[i].bytes[0] >=0x70 && insn[i].bytes[0] <= 0x7F) || //Short JCC
                (insn[i].bytes[0] == 0x0F && (insn[i].bytes[1] >= 0x80 && insn[i].bytes[1] <= 0x8F))) //Near JCC
        {
            // CALL, JMP, JCC 같은 제어문은 imm 필드에 주소가 있음, capstone이 미리 절대주소를 계산해줌
            orig_abs_addr = x86->operands[0].imm;      
        }

        //rip에 영향받지 않는(위치 독립적인) 일반 명령어들
        //오프셋 재계산 없이 바로 복사 가능
        else{
            accumulated_size += insn[i].size;
            trampoline_offset += insn[i].size;
            continue;
        }

        // 14바이트 뜯어오는 과정 중에 도착지가 있는지 확인 (내부 점프 판별)
        // (총 잘라올 길이를 아직 모르니 넉넉하게 20바이트 이내로 잡고 거름)
        bool is_internal = (orig_abs_addr >= (uint64_t)original_function) && 
                           (orig_abs_addr < (uint64_t)original_function + 20);
        if (is_internal) {
            printf("Internal jump detected! Hook failed.\n");
            cs_free(insn, count);
            cs_close(&handle);
            return false; 
        }

        //트램펄린 기준 오프셋 재계산
        //새 오프셋 = 원래 절대주소 - (현재 트램펄린 명령어 주소 + 현재 명령어 길이)
        new_offset = (int64_t)(orig_abs_addr-(tram_abs_addr+insn[i].size));

        //새 오프셋이 +-2GB범위 초과 시 훅 생성 실패
        if (new_offset >= INT32_MAX || new_offset <= INT32_MIN){
            return false;
        }

        // CALL, near JMP, near JCC 처리(4바이트 오프셋으로 점프하는 명령어들)
        if(insn[i].bytes[0] == 0xE8 ||
           insn[i].bytes[0] == 0xE9 || 
           (insn[i].bytes[0] == 0x0F && (insn[i].bytes[1] >= 0x80 && insn[i].bytes[1] <= 0x8F)))
        {
            // capstone이 알려주는 imm 오프셋 사용
            uint8_t imm_offset = x86->encoding.imm_offset;
            // 복사해둔 명령어의 imm 영역 덮어쓰기
            *(int32_t*)(&trampoline_buf[trampoline_offset + imm_offset]) = (int32_t)new_offset;
            //변경 전 명령어 길이와 동일 
            trampoline_offset += insn[i].size;
        }
        // short JMP
        else if(insn[i].bytes[0] == 0xEB)
        {
            *(uint8_t*)(&trampoline_buf[trampoline_offset]) = 0xE9; //Near JMP 명령어로 변경
            *(int32_t*)(&trampoline_buf[trampoline_offset + 1]) = new_offset;
            // short JMP(2byte) -> Near JMP(5byte)
            trampoline_offset += 5;
        }
        // short jCC
        else if(insn[i].bytes[0] >=0x70 && insn[i].bytes[0] <= 0x7F)
        {
            *(uint8_t*)(&trampoline_buf[trampoline_offset]) = 0x0F; //Near JCC 명령어로 변경
            *(uint8_t*)(&trampoline_buf[trampoline_offset + 1]) = insn[i].bytes[0] + 0x10; //각 조건에 대응되는(+0x10) Near JCC로 변경
            *(int32_t*)(&trampoline_buf[trampoline_offset + 2]) = new_offset;
            // short JCC(2byte) -> Near JCC(6byte)
            trampoline_offset += 6;
        } 
        //MOV, LEA, CMP, ADD와 같은 명령어 한꺼번에 처리
        else{
            //복사해둔 명령어 오프셋 위치를 새로구한 오프셋으로 변경
            //캡스톤이 알려주는 오프셋 위치(disp_offset)을 활용
            uint8_t disp_offset = x86->encoding.disp_offset;
            *(int32_t*)(&trampoline_buf[trampoline_offset + disp_offset]) = (int32_t)new_offset;
            //변경 전 명령어 길이와 동일 
            trampoline_offset += insn[i].size;
        }
        accumulated_size += insn[i].size;

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
    printf("HOOKED!!!! 0x11ef\n");
    target_func_t return_original= (target_func_t)trampoline_addr; 
    return return_original();
}

void setup_hook() {
    //먼저 디버거를 이용한 분석을 통해 target의 오프셋을 획득
    long target_offset = 0x11ef;

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