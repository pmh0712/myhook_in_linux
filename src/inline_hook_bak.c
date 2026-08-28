#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include "myutil.h"
#define TARGET_CALL_OFFSET 0x12ce //우회할 함수 호출 위치 오프셋, 모든 부분에서 우회할 꺼면 0으로 변경 

//프로그램의 base
long program_base;
//라이브러리 base
long libc_base;
//원본 strcmp 함수 주소를 저장할 포인터
int (*original_strcmp)(const char*, const char*) = NULL;
//트램펄린 코드 주소
void *trampoline_addr;
//64비트 환경에서 점프를 위한 점프 명령어 바이트 템플릿
unsigned char jmp_template[14] = {
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00, //JMP QWORD PTR [RIP+0] (현재 명령어 바로 뒤에 있는 8바이트 값을 읽어서 거기로 점프해라)
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
    }
}

void protect_memory(long target_addr)
{
    long page_size =  sysconf(_SC_PAGE_SIZE);
    long page_start = target_addr & ~(page_size - 1);

    // 쓰기 권한 해제
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC) == -1){
        perror("mprotect failed");
    }
}

void build_trampoline()
{
    /*
    0x00000000000a82e0 <+0>:     endbr64 
    0x00000000000a82e4 <+4>:     mov    rdx,QWORD PTR [rip+0x171bdd]        # 0x219ec8 <- rip 상대주소로 인해 트램펄린 오류 발생!
    0x00000000000a82eb <+11>:    mov    ecx,DWORD PTR [rdx+0xb8]
    0x00000000000a82f1 <+17>:    mov    esi,DWORD PTR [rdx+0x1a4]
    */
    int safe_len = 17; //strcmp에서 명령어기준 14바이트보다 큰 가장 작은 오프셋
    
    //mmap으로 트램펄린 공간 할당
    //rip 상대 주소로 기계어가 작동한다. mmap으로 할당한 위치에서 명령어를 실행하면 원본 코드가 기대하던 rip와 달라지기 때문에 오류 발생
    //따라서 rip에 따른 상대주소를 재계산 해야한다.
    //rip 상대 주소 점프의 범위(2GB)에 들어가기 위해, libc_base와 가까운 곳에 공간 할당
    void* hint_addr = (void*)(libc_base - 0x1000000); //libc_base - 16MB
    trampoline_addr = mmap(hint_addr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    //상대주소 재계산
    long original_code_rip = (long)original_strcmp+11;
    int original_offset = 0x171bdd;
    long mmap_code_rip = (long)trampoline_addr+11;
    int new_offset = original_code_rip + original_offset - mmap_code_rip;

    //원본 strcmp의 앞부분 17바이트를 트램펄린으로 복사
    memcpy(trampoline_addr, original_strcmp, safe_len);
    //new offset으로 상대주소 변경 
    //mov    rdx,QWORD PTR [rip+0x171bdd] => {0x48    0x8b    0x15    [0xdd    0x1b    0x17    0x00]}  상대주소 4바이트
    memcpy((void*)((long)trampoline_addr+7), &(new_offset), 4);

    //트램펄린 끝에서 다시 원본 strcmp함수의 18번째 바이트로 돌아갈 JMP명령어
    //돌아갈 주소 계산 (strcmp+17)
    long return_addr = (long)original_strcmp + safe_len;
    *(long*)(&jmp_template[6]) = return_addr;

    //복사해둔 17바이트 바로 뒤에 JMP 기계어 붙여넣기
    memcpy((void*)((long)trampoline_addr+safe_len), jmp_template, 14);
}

//우리가 덮어씌울 가짜 strcmp 함수
int mystrcmp(const char *s1, const char *s2)
{
    long target_strcmp_addr = program_base + TARGET_CALL_OFFSET;
    long ret_addr = (long)__builtin_return_address(0);
    
    //타겟이면 무조건 0을 반환
    if(TARGET_CALL_OFFSET == 0 || target_strcmp_addr == ret_addr){
        printf("HOOKED! \"%s\" vs \"%s\"\n", s1, s2);
        return 0; 
    }

    int (*return_strcmp)(const char*, const char*) = (int(*)(const char*, const char*))trampoline_addr; 
    return return_strcmp(s1, s2);
}

void setup_hook() {
    //메모리에서 진짜 strcmp의 주소를 찾아 저장해둠
    original_strcmp = dlsym(RTLD_DEFAULT, "strcmp");

    if(original_strcmp == NULL){
        printf("dlsym failed!: %s\n", dlerror());
        return;
    }
    printf("[*] dlsym found original_strcmp at: %p\n", original_strcmp);

    //프로그램, 라이브러리의 base를 획득
    pid_t mypid = getpid();
    program_base = get_base(mypid, NULL);
    libc_base = get_base(mypid, "libc.so.6");
    printf("[*] program_base: 0x%lx, libc_base: 0x%lx\n", program_base, libc_base);

    //쓰기 권한 변경
    unprotect_memory((long)original_strcmp);
    //트램펄린 생성
    build_trampoline();
    //변경할 훅 함수 주소
    long mystrcmp_addr = (long)mystrcmp;

    //6번 인덱스에 훅 함수의 주소를 저장
    *(long*)(&jmp_template[6])=mystrcmp_addr;
    //mprotect로 쓰기 권한을 얻은 공간에 overwrite
    memcpy((void*)original_strcmp, jmp_template, 14);
    //쓰기권한 해제
    protect_memory((long)original_strcmp);

    printf("[+] HOOK SETUP DONE!\n");
}

//라이브러리가 dlopne으로 로드되자 마자 '자동으로' 실행되는 초기화 함수
__attribute__((constructor))
void on_library_loaded(){
    // 밖에서 dlopne이 성공하는 즉시 이 코드가 자동으로 실행됨
    setup_hook();
}