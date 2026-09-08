#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include "myutil.h"
#define HOOK_JMP_OFFSET 43

typedef enum 
{   PATCH_NONE, 
    PATCH_RIP_DATA, 
    PATCH_INTERNAL, 
    PATCH_EXPAND_JMP, 
    PATCH_EXPAND_JCC, 
    PATCH_NEAR_BRANCH
}PATCH_TYPE;

typedef struct inst_info
{
    uint64_t original_addr;
    uint64_t dest_abs_addr;
    int trampoline_offset;
    uint8_t orig_size;
    uint8_t expand_size;
    uint8_t patch_offset;
    PATCH_TYPE patch_type;
} INST_INFO;

//훅 상태 개체
typedef struct hook_context
{
    void* original_function; //타겟 함수 원래 주소
    void* hook_function;     //내가 만든 훅 함수 주소
    void* trampoline_addr;   //할당받은 트램펄린 주소

    size_t stolen_byte_size;     //잘라낸 명령어의 길이
    size_t relocated_len;   //분석 후 확장된 명령어의 길이
    size_t backup_stub_size;        //레지스터 백업 스텁 길이
    size_t final_trampoline_len; //최종 트램펄린 길이

    size_t stolen_inst_count; // 트램펄린으로 훔쳐갈 실제 명령어 개수
} HOOK_CONTEXT;

//14바이트 점프 명령어 템플릿
const unsigned char JMP_TEMPLATE[14] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  //JMP QWORD PTR [RIP+0] (현재 명령어 바로 뒤에 있는 8바이트 값을 읽어서 거기로 점프해라)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 우리가 직접 채워 넣을 8바이트 절대 주소 공간
};

// 총 80바이트짜리 레지스터 백업/복구 및 훅 호출 템플릿
const unsigned char HOOK_STUB_TEMPLATE[80] = {
    // [1] Context Save (RFLAGS & 범용 레지스터 15개 백업)
    0x9c,                                           // pushfq (상태 레지스터 백업)
    0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,       // push rax, rcx, rdx, rbx, rbp, rsi, rdi
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push r8, r9, r10, r11
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, // push r12, r13, r14, r15

    // [2] Stack Alignment & Arg Setup
    0x49, 0x89, 0xe4,                               // mov r12, rsp (현재 SP를 r12에 임시 저장)
    0x48, 0x83, 0xe4, 0xf0,                         // and rsp, 0xfffffffffffffff0 (16바이트 정렬)
    0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00,       // sub rsp, 128 (레드존 보호)
    0x4c, 0x89, 0xe7,                               // mov rdi, r12 (백업된 레지스터 구조체 포인터를 인자로 전달)

    // [3] Call myfunction
    0x48, 0xb8,                                     // movabs rax, [아래 8바이트 주소]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ★ [INDEX 43] myfunction 8바이트 주소 주입 공간
    0xff, 0xd0,                                     // call rax

    // [4] Stack Restore
    0x4c, 0x89, 0xe4,                               // mov rsp, r12 (스택 포인터 원상복구)

    // [5] Context Restore (역순 pop)
    0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, // pop r15, r14, r13, r12
    0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, // pop r11, r10, r9, r8
    0x5f, 0x5e, 0x5d, 0x5b, 0x5a, 0x59, 0x58,       // pop rdi, rsi, rbp, rbx, rdx, rcx, rax
    0x9d                                           // popfq (상태 레지스터 복구)
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

/**
 * @brief 명령어가 RIP 레지스터 상대 주소 참조를 사용하는지 판별
 * 
 * x64 PIE(Position Independent Executable) 환경에서 전역 변수나 문자열을 참조할 때
 * `mov rax, [rip + 0x1234]` 형태를 자주 사용한다. Capstone의 x86_op_mem 구조체를 
 * 검사하여 베이스 레지스터가 RIP인지 확인한다.
 */
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
 * @brief 64비트 절대 주소 점프(14바이트 릴레이)를 위한 트램펄린 메모리 할당
 * 
 * x64 환경에서 RIP 상대 참조 및 JMP/CALL 명령어는 +-2GB(INT32) 범위 내에서만 뛸 수 있다.
 * 따라서 타겟 함수 주소(target_addr)를 기준으로 위아래 2GB 영역 내에서
 * mmap을 이용해 빈 메모리 공간을 탐색하고 할당한다.
 * 
 * @param target_addr 훅을 걸 원본 함수의 주소 (탐색 기준점)
 * @return void* 할당된 트램펄린 메모리의 시작 주소 (실패 시 NULL)
 */
void* allocation_for_trampoline(uint64_t target_addr)
{
    void* allocated_addr = NULL;
    uint64_t base_addr = target_addr & ~(0xFFF); //mmap할당 규칙에 맞춘 마스킹
    bool flag = false;
    for(long n = 1; (n * 0x1000)< INT32_MAX; n++){
        for (int sign = 1; sign > -2; sign -= 2){
            void* hint_addr = (void*)(base_addr + sign * n * 0x1000);
            void* test_addr = mmap(hint_addr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

            if(test_addr == MAP_FAILED) continue;

            //2GB 바깥에 트램펄린이 생성 시 훅 생성 실패
            long distance = (long)test_addr - (long)target_addr;

            if(distance >= INT32_MIN && distance <= INT32_MAX){
                flag = true;
                allocated_addr = test_addr;
                break;
            }
            munmap(test_addr, 0x1000);
        }

        if (flag) break;
    }
    return allocated_addr;
}

/**
 * @brief 훔쳐온 명령어 배열 내부에서 타겟 주소의 인덱스를 탐색 (내부 분기용)
 * 
 * 트램펄린 내부로 점프(PATCH_INTERNAL)하는 명령어의 경우,
 * 원래 점프하려던 타겟 주소가 1_PASS에서 분석한 배열(inst_info)의 몇 번째 인덱스인지 찾는다.
 * 이를 통해 트램펄린 내에서의 새로운 도착지 오프셋을 계산할 수 있다.
 */
int search_destination(uint64_t orig_abs_addr, INST_INFO* inst_info, size_t count)
{
    int j = 0;
    for(; j < count; j++){
        if((uint64_t)inst_info[j].original_addr == orig_abs_addr) break;
    }
    if (j == count) {printf("can't find destination address!\n"); return -1;}
    return j;
}

/**
 * @brief 1차 패스 (탐색 및 분석)
 * 
 * 타겟 함수의 프롤로그를 디코딩하여 트램펄린에 덮어쓸 최소 14바이트 이상의 영역을 확보한다.
 * 이 단계에서는 실제 메모리 복사를 수행하지 않으며, 각 명령어의 속성을 분석해
 * 2차 패스에서 사용할 메타데이터(팽창 크기, 패치 타입, 트램펄린 내 오프셋)를 inst_info에 기록한다.
 * 
 * [핵심 로직]
 * - 길이 확보: 가변 길이 명령어를 자르다 보면 14바이트를 초과할 수 있으므로, 훔쳐갈 실제 바이트 수(stolen_byte_size)와 명령어 개수(stolen_inst_count)를 확정
 * - 내부/외부 분기 판별: 분기문의 목적지가 우리가 훔쳐갈 명령어들(prologue 영역) 내부인지 외부인지 판별
 * - 팽창(Expansion) 예측: 외부로 뛰는 Short JMP(2b)/JCC(2b)는 거리가 멀어질 것에 대비해 트램펄린에서 Near JMP(5b)/JCC(6b)로 팽창하도록 크기 예약
 * 
 * @return bool 14바이트 이상 확보 성공 여부
 */
bool analyze_insts(HOOK_CONTEXT* ctx, INST_INFO* inst_info, cs_insn *insn)
{
    size_t measured_byte_size = 0;
    size_t trampoline_offset = 0;
    size_t parsed_inst_count = 0;

    for(int i = 0; i < ctx->stolen_inst_count && measured_byte_size < 14;i++){
        measured_byte_size += insn[i].size;
        parsed_inst_count++;
    }
    if (measured_byte_size < 14) return false;
    ctx->stolen_byte_size = measured_byte_size;
    ctx->stolen_inst_count = parsed_inst_count;

    uint64_t prologue_start = insn[0].address;
    uint64_t prologue_end = prologue_start + ctx->stolen_byte_size;

    for(int i = 0; i < ctx->stolen_inst_count; i++){
        cs_x86 *x86 =  &(insn[i].detail->x86);
        inst_info[i].original_addr = (uint64_t)insn[i].address;
        inst_info[i].trampoline_offset = trampoline_offset;
        inst_info[i].orig_size = insn[i].size;

        //rip 레지스터 상대주소 지정(rip + offset)을 쓰는 명령어들
        if(is_rip_relative(&insn[i])){
            // MOV, LEA 같은 데이터 참조문은 disp를 더해서 직접 계산해야 함, capstone이 미리 만들어 주지 않음
            inst_info[i].dest_abs_addr = insn[i].address + insn[i].size + x86->disp;
            inst_info[i].expand_size = insn[i].size;
            inst_info[i].patch_offset = x86->encoding.disp_offset;
            inst_info[i].patch_type = PATCH_RIP_DATA;
            trampoline_offset += insn[i].size;
        }

        
        else if(insn[i].bytes[0] == 0xE8 || //Direct CALL
                insn[i].bytes[0] == 0xEB || // Near JMP
                insn[i].bytes[0] == 0xE9 || // Short JMP
                (insn[i].bytes[0] >= 0x70 && insn[i].bytes[0] <= 0x7F) || //Short JCC
                (insn[i].bytes[0] == 0x0F && (insn[i].bytes[1] >= 0x80 && insn[i].bytes[1] <= 0x8F))) //Near JCC
        {
            // 점프해서 도착하는 곳
            // 분기문은 imm 필드에 목적지 주소가 있음. Capstone이 현재 명령어 주소를 기준으로 절대 주소를 산출해 둔 상태임
            inst_info[i].dest_abs_addr = x86->operands[0].imm;
            inst_info[i].patch_offset = x86->encoding.imm_offset;

            // 점프/분기문인 경우 트램펄린에서 트램펄린 내부로 점프해야하는 경우가 존재함
            // 잘라낸 명령어 안으로 점프하는 경우 명령어 길이의 변화는 없다.
            if(inst_info[i].dest_abs_addr >= prologue_start && inst_info[i].dest_abs_addr < prologue_end){
                inst_info[i].expand_size = insn[i].size;
                inst_info[i].patch_type = PATCH_INTERNAL;
                trampoline_offset += insn[i].size;
            }

            // 잘라낸 명령어 바깥으로 점프하는 경우,
            //short JCC와 short JMP의 경우 Near JVV, Near JMP로 명령어가 바뀌어 명령어 길이의 변화가 발생한다.
            else{
                //Short JMP(2bytes) -> Near JMP(5bytes)
                if(insn[i].bytes[0] == 0xEB){ 
                    inst_info[i].expand_size = 5;
                    inst_info[i].patch_type = PATCH_EXPAND_JMP;
                    trampoline_offset += 5;
                }
                //Short JCC(2bytes) -> Near JCC(6bytes)
                else if(insn[i].bytes[0] >=0x70 && insn[i].bytes[0] <= 0x7F){ 
                    inst_info[i].expand_size = 6;
                    inst_info[i].patch_type = PATCH_EXPAND_JCC;
                    trampoline_offset += 6;
                }
                //이외 점프문/분기문은 잘라낸 명령어 바깥으로 점프해도 팽창하지 않음
                else {
                    inst_info[i].expand_size = insn[i].size;
                    inst_info[i].patch_type = PATCH_NEAR_BRANCH;
                    trampoline_offset += insn[i].size;
                }

            }
        }
        // 분기문/점프문이 아닌 명령어들은 그대로간다
        else{
            inst_info[i].dest_abs_addr = 0;  //참조하거나 점프 목적지가 없으므로 0
            inst_info[i].expand_size = insn[i].size; //명령어 길이 유지
            inst_info[i].patch_offset = 0;   //바꾸어야할 부분이 없으니 0
            inst_info[i].patch_type = PATCH_NONE;
            trampoline_offset += insn[i].size;
        }
    }
    return true;
}

/**
 * @brief 2차 패스 (명령어 복사 및 릴로케이션)
 * 
 * 1차 패스의 분석 결과를 바탕으로 트램펄린 버퍼에 명령어를 실제 복사하고,
 * 위치 독립성이 깨진 명령어들의 오프셋(RIP 상대 주소)을 트램펄린 기준으로 재계산하여 패치한다.
 * 
 * [주소 릴로케이션 원리]
 * 1. 데이터 참조문 (MOV, LEA 등): 현재 트램펄린 주소 기준으로 새 오프셋 계산 후 덮어쓰기
 * 2. 내부 분기문: 훔쳐온 명령어들 사이의 점프이므로, 트램펄린 내부의 팽창된 길이를 반영하여 상대 거리(int8_t) 보정
 * 3. 외부 분기문 (명령어 팽창 및 RIP 보정):
 *    - Short 분기문을 Near 분기문(5~6바이트)으로 기계어 패치 (0xE9 또는 0x0F 0x8X)
 *    - 💡 [중요] 새 오프셋 계산 공식: `목적지 절대 주소 - (현재 트램펄린 명령어 주소 + 팽창된 명령어 크기)`
 *      명령어가 팽창한 만큼 CPU가 다음 명령어를 읽을 때의 RIP가 뒤로 밀리므로, 팽창된 최종 크기(expand_size)를 빼주어 오프셋을 정확히 맞춤.
 * 
 * @return bool 오프셋이 +-2GB(INT32) 범위를 벗어나지 않고 정상적으로 릴로케이션 되었는지 여부
 */
bool build_relocated_trampoline(HOOK_CONTEXT* ctx, INST_INFO* inst_info)
{
    uint8_t *trampoline_ptr = (uint8_t*)ctx->trampoline_addr + ctx->backup_stub_size; // 레지스터 상태 저장/복구 파트 반영

    // 최소 14바이트가 넘을 때까지 원본 명령어를 몇 개 뜯어올지 계산
    for (size_t i = 0; i < ctx->stolen_inst_count; i++){
        long tram_rel_offset = inst_info[i].trampoline_offset;
        // 명령어 복사
        memcpy((void*)(&trampoline_ptr[tram_rel_offset]), (void*)inst_info[i].original_addr, inst_info[i].orig_size);
        //트램펄린의 현재 명령어 절대주소
        uint64_t tram_abs_addr = (uint64_t)(trampoline_ptr + tram_rel_offset);
        // 새로 갱신할 offset
        int64_t patched_offset = inst_info[i].dest_abs_addr - (tram_abs_addr + inst_info[i].expand_size);

        if (!(inst_info[i].patch_type == PATCH_NONE) && !(inst_info[i].patch_type == PATCH_INTERNAL)){
            //점프하거나 참조해야할 주소의 새 오프셋이 +-2GB범위 초과 시 훅 생성 실패
            if (patched_offset >= INT32_MAX || patched_offset <= INT32_MIN){
                printf("allocation fail in 2GB distance\n");
                return false;
            }
        }

        switch (inst_info[i].patch_type)
        {
            case PATCH_NONE:
                break;
            case PATCH_INTERNAL:{
                int idx = search_destination(inst_info[i].dest_abs_addr, inst_info, ctx->stolen_inst_count);
                if(idx == -1) return 0;
                int8_t short_offset = inst_info[idx].trampoline_offset - (tram_rel_offset + inst_info[i].expand_size); 
                trampoline_ptr[tram_rel_offset+inst_info[i].patch_offset] = short_offset;
                break;
            }
            case PATCH_NEAR_BRANCH:
            case PATCH_RIP_DATA:
                printf("is it RIP right? %d, %lx\n", inst_info[i].patch_type, patched_offset);
                *(int32_t*)(&trampoline_ptr[tram_rel_offset + inst_info[i].patch_offset]) = patched_offset;
                break;
            case PATCH_EXPAND_JMP:
                trampoline_ptr[tram_rel_offset] = 0xE9; //Near JMP 명령어로 변경
                *(int32_t*)(&trampoline_ptr[tram_rel_offset + 1]) = patched_offset;
                break;
            case PATCH_EXPAND_JCC:{
                uint8_t control_op = trampoline_ptr[tram_rel_offset];
                trampoline_ptr[tram_rel_offset] = 0x0F; //Near JCC 명령어로 변경
                trampoline_ptr[tram_rel_offset + 1] = control_op + 0x10; //각 조건에 대응되는(+0x10) Near JCC로 변경
                *(int32_t*)(&trampoline_ptr[tram_rel_offset + 2]) = patched_offset;
                break;
            }
            default: 
                printf("1PASS result error!!\n");
                break;
        }
        ctx->relocated_len += inst_info[i].expand_size;
    }
    return true;
} 

/**
 * @brief 인라인 훅(Inline Hook)을 위한 트램펄린 동적 생성 및 명령어 릴로케이션
 * 
 * 타겟 함수의 프롤로그를 디코딩하여 트램펄린 버퍼를 할당받고 코드를 구성한다.
 * 레지스터 백업 스텁, 릴로케이션된 원본 명령어, 원본 함수 복귀 JMP로 이루어진다.
 * 
 * [구성 순서]
 *   1. Capstone 디스어셈블러 초기화 및 타겟 함수 프롤로그 디코딩
 *   2. 타겟 함수 주변 +-2GB 내에 트램펄린 메모리(mmap) 할당
 *   3. 트램펄린 앞단에 레지스터 백업 스텁(80바이트) 주입
 *   4. 1_PASS (분석) 수행 후 메모리 누수 방지를 위해 Capstone 자원 즉시 해제
 *   5. 2_PASS (복사 및 릴로케이션) 수행
 *   6. 트램펄린 끝단에 원본 함수 미실행 영역으로 돌아가는 14바이트 절대 JMP 주입
 * 
 * @return bool 트램펄린 생성 성공 여부
 */
bool build_trampoline(HOOK_CONTEXT *ctx)
{
    //capstone 변수 세팅
    csh handle;   //capstone 세션핸들
    cs_insn *insn;//어셈블리 명령어를 담는 구조체

    // x86_64모드로 캡스톤 초기화
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        printf("capstone initializing fail!!\n");
        return false;
    }

    // 디스어셈블 전에 상세 옵션을 켜기 -> 상대주소 사용 유무 구별 
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // 훅을 걸기위해 14바이트 이상 명령어를 덮어써야함
    // 널널하게 32바이트 정도 디스어셈블
    ctx->stolen_inst_count = cs_disasm(handle, (const uint8_t*)ctx->original_function, 32, (uint64_t)ctx->original_function, 0, &insn);

    if (ctx->stolen_inst_count == 0){
        printf("disasmble failed!!\n");
        return false;
    }

    // 트램펄린 공간 할당
    ctx->trampoline_addr = allocation_for_trampoline((uint64_t)ctx->original_function);
    if (ctx->trampoline_addr == NULL) return false;

    uint8_t* tram_base_ptr = (uint8_t*)ctx->trampoline_addr;
    //레지스터 백업 스텁 세팅
    memcpy((void*)tram_base_ptr, HOOK_STUB_TEMPLATE, 80);
    // 훅 함수 저장
    *(uint64_t*)(&tram_base_ptr[HOOK_JMP_OFFSET]) = (uint64_t)ctx->hook_function;
    printf("myfunction: %lx\n", (long)ctx->hook_function);
    ctx->backup_stub_size = 80;
    ctx->final_trampoline_len += ctx->backup_stub_size;
    
    INST_INFO inst_info[32] = {0};
    if (!analyze_insts(ctx, inst_info, insn)){
        printf("this function is too short!! (function length < 14bytes)\n");
        cs_free(insn, ctx->stolen_inst_count);
        cs_close(&handle);
        return false;
    }

    cs_free(insn, ctx->stolen_inst_count); 
    cs_close(&handle);

     if (!build_relocated_trampoline(ctx, inst_info)){
        return false;
     }
     printf("ctx->relocated_len: %ld\n", ctx->relocated_len);
     ctx->final_trampoline_len += ctx->relocated_len;

    // 원본 함수의 훔쳐온 영역(14바이트) 바로 다음으로 복귀하는 점프 명령어 세팅
    unsigned char jmp_return_orig[14];
    memcpy(jmp_return_orig, JMP_TEMPLATE, 14);

    // 돌아갈 주소 계산 및 JMP 조립 (64비트 절대주소 점프) -> 잘라온 명령어 만큼 주소 계산
    long return_addr = (long)ctx->original_function + ctx->stolen_byte_size;
    *(long*)(&jmp_return_orig[6]) = return_addr;

    // 만들어진 트램펄린 바로 뒤에 JMP 기계어 이어 붙이기 -> 명령어의 길이 변화로 잘라낸 명령어보다 트램펄린의 길이가 길어지므로 트램펄린의 최종 길이를 사용 
    memcpy((void*)((long)ctx->trampoline_addr + ctx->final_trampoline_len), jmp_return_orig, 14);
    ctx->final_trampoline_len += 14;
    return true;
}

//우리가 실행시킬 훅 함수
void myfunction(void)
{
    printf("HOOKED!!!! 0x12f6\n");
}

void setup_hook() {
    //먼저 디버거를 이용한 분석을 통해 target의 오프셋을 획득
    long target_offset = 0x12f6;

    //프로그램, 라이브러리의 base를 획득
    pid_t mypid = getpid();
    printf("get pid %d\n", mypid);
    //프로그램의 base
    long program_base = get_base_sys(mypid, NULL);
    //라이브러리 base
    long libc_base = get_base_sys(mypid, "libc.so.6");

    // 훅 상태 객체 생성
    HOOK_CONTEXT ctx = {0};
    // 원본 함수 저장
    ctx.original_function =  (void*)(program_base + target_offset);
    // 훅 함수 주소 저장
    ctx.hook_function = (void*)myfunction;
    printf("[*] program_base: 0x%lx, libc_base: 0x%lx, target_address: 0x%lx\n", program_base, libc_base, (long)ctx.original_function);


    //쓰기 권한 변경
    unprotect_memory((long)ctx.original_function);
    //트램펄린 생성
    if(!build_trampoline(&ctx)){
        printf("build trampoline fail!!\n");
        return;
    }
    printf("trampoline_addr: 0x%lx\n", (long)ctx.trampoline_addr);
    //원본 함수의 프롤로그를 덮어써서 트램펄린으로 진입하게 만드는 14바이트 점프 패치
    unsigned char jmp_hook_patch[14];
    memcpy(jmp_hook_patch, JMP_TEMPLATE, 14);

    //6번 인덱스에 훅 함수의 주소를 저장
    *((uint64_t*)(&jmp_hook_patch[6])) = (uint64_t)ctx.trampoline_addr;
    //mprotect로 쓰기 권한을 얻은 공간에 overwrite
    memcpy((void*)ctx.original_function, jmp_hook_patch, 14);
    //쓰기권한 해제
    protect_memory((long)ctx.original_function);

    printf("[+] HOOK SETUP DONE!\n");
}

//라이브러리가 dlopne으로 로드되자 마자 '자동으로' 실행되는 초기화 함수
__attribute__((constructor))
void on_library_loaded(){
    // 밖에서 dlopne이 성공하는 즉시 이 코드가 자동으로 실행됨
    setup_hook();
}