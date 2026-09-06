#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include "myutil.h"

typedef enum 
{   PATCH_NONE, 
    PATCH_RIP_DATA, 
    PATCH_INTERNAL, 
    PATCH_EXPAND_JMP, 
    PATCH_EXPAND_JCC, 
    PATCH_NEAR_BRANCH
}PATCH_TYPE;

struct inst_info
{
    uint64_t original_addr;
    uint64_t orig_abs_addr;
    int trampoline_offset;
    uint8_t orig_size;
    uint8_t expand_size;
    uint8_t patch_offset;
    PATCH_TYPE patch_type;
};

typedef struct inst_info INST_INFO;

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
INST_INFO ONE_PASS_RESULT[32];

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

int search_destination(uint64_t orig_abs_addr, size_t count)
{
    int j = 0;
    for(; j < count; j++){
        if((uint64_t)ONE_PASS_RESULT[j].original_addr == orig_abs_addr) break;
    }
    if (j == count) {printf("can't find destination address!\n"); return -1;}
    return j;
}

/**
 * @brief 1차 패스 (탐색 및 분석)
 * 
 * 타겟 함수의 프롤로그를 분석하여 최소 14바이트를 확보한다.
 * 이 단계에서는 실제 메모리 복사를 수행하지 않고, 각 명령어의 속성과 
 * 트램펄린 내에서의 예상 오프셋을 계산하여 ONE_PASS_RESULT 구조체에 저장한다.
 * 
 * [핵심 로직]
 * - 14바이트 확보: 가변 길이 명령어를 자르다 보면 14바이트를 초과할 수 있으므로 정확한 원본 길이(total_len) 측정
 * - 내부/외부 분기 판별: 분기문의 목적지가 우리가 훔쳐올 14바이트 내부인지 외부인지 판별
 * - 팽창(Expansion) 예측: 외부로 뛰는 Short JMP(2b)/JCC(2b)는 트램펄린에서 Near JMP(5b)/JCC(6b)로 
 *   팽창하므로, 이를 미리 계산해 두어야 내부 점프 오프셋 계산이 꼬이지 않음
 */
size_t one_PASS(cs_insn *insn, size_t count)
{
    size_t accumulated_size = 0;
    size_t trampoline_offset = 0;
    size_t total_len = 0;

    for(int i = 0; i < count && total_len < 14;i++){
        total_len += insn[i].size;
    }

    uint64_t prologue_start = insn[0].address;
    uint64_t prologue_end = prologue_start + total_len;

    for(int i = 0; i < count && accumulated_size < 14; i++){
        cs_x86 *x86 =  &(insn[i].detail->x86);
        ONE_PASS_RESULT[i].original_addr = (uint64_t)insn[i].address;
        ONE_PASS_RESULT[i].trampoline_offset = trampoline_offset;
        ONE_PASS_RESULT[i].orig_size = insn[i].size;

        //rip 레지스터 상대주소 지정(rip + offset)을 쓰는 명령어들
        if(is_rip_relative(&insn[i])){
            // MOV, LEA 같은 데이터 참조문은 disp를 더해서 직접 계산해야 함, capstone이 미리 만들어 주지 않음
            ONE_PASS_RESULT[i].orig_abs_addr = insn[i].address + insn[i].size + x86->disp;
            ONE_PASS_RESULT[i].expand_size = insn[i].size;
            ONE_PASS_RESULT[i].patch_offset = x86->encoding.disp_offset;
            ONE_PASS_RESULT[i].patch_type = PATCH_RIP_DATA;
        }

        
        else if(insn[i].bytes[0] == 0xE8 || //Direct CALL
                insn[i].bytes[0] == 0xEB || // Near JMP
                insn[i].bytes[0] == 0xE9 || // Short JMP
                (insn[i].bytes[0] >= 0x70 && insn[i].bytes[0] <= 0x7F) || //Short JCC
                (insn[i].bytes[0] == 0x0F && (insn[i].bytes[1] >= 0x80 && insn[i].bytes[0] <= 0x8F))) //Near JCC
        {
            // 점프해서 도착하는 곳
            // CALL, JMP, JCC 같은 제어문은 imm 필드에 주소가 있음, capstone이 미리 절대주소를 계산해줌
            ONE_PASS_RESULT[i].orig_abs_addr = x86->operands[0].imm;
            ONE_PASS_RESULT[i].patch_offset = x86->encoding.imm_offset;

            // 점프/분기문인 경우 트램펄린에서 트램펄린 내부로 점프해야하는 경우가 존재함
            // 잘라낸 명령어 안으로 점프하는 경우 명령어 길이의 변화는 없다.
            if(ONE_PASS_RESULT[i].orig_abs_addr >= prologue_start && ONE_PASS_RESULT[i].orig_abs_addr < prologue_end){
                ONE_PASS_RESULT[i].expand_size = insn[i].size;
                ONE_PASS_RESULT[i].patch_type = PATCH_INTERNAL;
                trampoline_offset += insn[i].size;
            }

            // 잘라낸 명령어 바깥으로 점프하는 경우,
            //short JCC와 short JMP의 경우 Near JVV, Near JMP로 명령어가 바뀌어 명령어 길이의 변화가 발생한다.
            else{
                //Short JMP(2bytes) -> Near JMP(5bytes)
                if(insn[i].bytes[0] == 0xEB){ 
                    ONE_PASS_RESULT[i].expand_size = 5;
                    ONE_PASS_RESULT[i].patch_type = PATCH_EXPAND_JMP;
                    trampoline_offset += 5;
                }
                //Short JCC(2bytes) -> Near JCC(6bytes)
                else if(insn[i].bytes[0] >=0x70 && insn[i].bytes[0] <= 0x7F){ 
                    ONE_PASS_RESULT[i].expand_size = 6;
                    ONE_PASS_RESULT[i].patch_type = PATCH_EXPAND_JCC;
                    trampoline_offset += 6;
                }
                //이외 점프문/분기문은 잘라낸 명령어 바깥으로 점프해도 팽창하지 않음
                else {
                    ONE_PASS_RESULT[i].expand_size = insn[i].size;
                    ONE_PASS_RESULT[i].patch_type = PATCH_NEAR_BRANCH;
                    trampoline_offset += insn[i].size;
                }

            }
        }
        // 분기문/점프문이 아닌 명령어들은 그대로간다
        else{
            ONE_PASS_RESULT[i].orig_abs_addr = 0;  //참조하거나 점프 목적지가 없으므로 0
            ONE_PASS_RESULT[i].expand_size = insn[i].size; //명령어 길이 유지
            ONE_PASS_RESULT[i].patch_offset = 0;   //바꾸어야할 부분이 없으니 0
            ONE_PASS_RESULT[i].patch_type = PATCH_NONE;
            trampoline_offset += insn[i].size;
        }
        accumulated_size += insn[i].size;
    }

    return total_len;
}

/**
 * @brief 2차 패스 (명령어 복사 및 릴로케이션)
 * 
 * one_PASS의 분석 결과를 바탕으로 트램펄린에 명령어를 복사하고,
 * 위치 독립성이 깨진 명령어들의 오프셋을 트램펄린 기준으로 재계산하여 패치한다.
 * 
 * [주소 릴로케이션 원리]
 * 1. 데이터 참조문 (MOV, LEA 등): capstone의 disp 값을 활용하여 절대 주소를 구한 뒤 재계산
 * 2. 내부 분기문: 훔쳐온 명령어들 사이의 상대 거리를 트램펄린 내부의 거리로 보정
 * 3. 외부 분기문 (명령어 팽창 및 RIP 보정):
 *    - Short 분기문은 거리가 멀어질 수 있으므로 Near 분기문으로 변경 (2바이트 -> 5/6바이트 팽창)
 *    - 💡 [중요] 명령어가 팽창한 만큼 CPU가 명령어를 읽은 후의 RIP(PC)가 앞으로 밀려남.
 *      따라서 원래 목적지를 정확히 가리키려면 팽창된 바이트 수만큼 오프셋에서 빼주어야 함.
 *      - Short JMP (2->5) : 오프셋 - 3
 *      - Short JCC (2->6) : 오프셋 - 4
 * 
 * @return size_t 팽창(Expansion)이 모두 반영된 트램펄린의 최종 명령어 길이
 */
size_t two_PASS(size_t count)
{
    uint8_t *trampoline_ptr = (uint8_t*)trampoline_addr;
    size_t accumulated_size = 0;
    size_t trampoline_size = 0;

    // 최소 14바이트가 넘을 때까지 원본 명령어를 몇 개 뜯어올지 계산
    for (size_t i = 0; i < count && accumulated_size < 14; i++){
        long t_offset = ONE_PASS_RESULT[i].trampoline_offset;
        // 명령어 복사
        memcpy((void*)(&trampoline_ptr[t_offset]), (void*)ONE_PASS_RESULT[i].original_addr, ONE_PASS_RESULT[i].orig_size);
        //트램펄린의 현재 명령어 절대주소
        uint64_t tram_abs_addr = (long)trampoline_addr + t_offset;
        // 새로 갱신할 offset
        int64_t new_offset = ONE_PASS_RESULT[i].orig_abs_addr - (tram_abs_addr + ONE_PASS_RESULT[i].expand_size);

        if (!(ONE_PASS_RESULT[i].patch_type == PATCH_NONE) && !(ONE_PASS_RESULT[i].patch_type == PATCH_INTERNAL)){
            //점프하거나 참조해야할 주소의 새 오프셋이 +-2GB범위 초과 시 훅 생성 실패
            if (new_offset >= INT32_MAX || new_offset <= INT32_MIN){
                printf("allocation fail in 2GB distance\n");
                return 0;
            }
        }

        switch (ONE_PASS_RESULT[i].patch_type)
        {
            case PATCH_NONE:
                trampoline_size += ONE_PASS_RESULT[i].expand_size;
                break;
            case PATCH_INTERNAL:{
                int idx = search_destination(ONE_PASS_RESULT[i].orig_abs_addr, count);
                if(idx == -1) return 0;
                uint8_t short_offset = ONE_PASS_RESULT[idx].trampoline_offset - (t_offset + ONE_PASS_RESULT[i].expand_size); 
                trampoline_ptr[t_offset+ONE_PASS_RESULT[i].patch_offset] = short_offset;
                trampoline_size += ONE_PASS_RESULT[i].expand_size;
                break;
            }
            case PATCH_NEAR_BRANCH:
            case PATCH_RIP_DATA:
                *(int32_t*)(&trampoline_ptr[t_offset+ONE_PASS_RESULT[i].patch_offset]) = new_offset;
                trampoline_size += ONE_PASS_RESULT[i].expand_size;
                break;
            case PATCH_EXPAND_JMP:
                trampoline_ptr[t_offset] = 0xE9; //Near JMP 명령어로 변경
                *(int32_t*)(&trampoline_ptr[t_offset + 1]) = new_offset;
                trampoline_size += 5;
                break;
            case PATCH_EXPAND_JCC:{
                uint8_t control_op = trampoline_ptr[t_offset];
                trampoline_ptr[t_offset] = 0x0F; //Near JCC 명령어로 변경
                trampoline_ptr[t_offset + 1] = control_op + 0x10; //각 조건에 대응되는(+0x10) Near JCC로 변경
                *(int32_t*)(&trampoline_ptr[t_offset + 2]) = new_offset;
                trampoline_size += 6;
                break;
            }
            default: 
                printf("1PASS result error!!\n");
                break;
        }
        accumulated_size += ONE_PASS_RESULT[i].orig_size;
    }
    return trampoline_size;
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

    size_t original_len = one_PASS(insn, count);

    if ((original_len) < 14){
        printf("this function is too short!! (function length < 14bytes)\n");
        cs_free(insn, count);
        cs_close(&handle);
        return false;
    }

    size_t final_len = two_PASS(count);
     if (final_len < 14){
        cs_free(insn, count);
        cs_close(&handle);
        return false;
     }
     printf("final_len: %ld\n", final_len);

    //트램펄린으로 점프하기위한 점프 명령어 세팅
    unsigned char jmp_trampoline[14];
    memcpy(jmp_trampoline, JMP_TEMPLATE, 14);

    // 돌아갈 주소 계산 및 JMP 조립 (64비트 절대주소 점프) -> 잘라온 명령어 만큼 주소 계산
    long return_addr = (long)original_function + original_len;
    *(long*)(&jmp_trampoline[6]) = return_addr;

    // 복사한 14바이트 바로 뒤에 JMP 기계어 이어 붙이기 -> 명령어의 길이 변화로 잘라낸 명령어보다 트램펄린의 길이가 길어지므로 트램펄린의 길이를 사용 
    memcpy((void*)((long)trampoline_addr + final_len), jmp_trampoline, 14);
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
    printf("trampoline_addr: 0x%lx\n", (long)trampoline_addr);
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