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


// dlsym이 반환해주는 strcmp 주소는 IFUNC(Indirect Function)로 인해
// CPU 하드웨어 지원 설정에 따라 런타임에 동적으로 결정되는 실제 함수의 진입점이므로,
// 이 주소를 기준으로 처음 몇 바이트의 명령어를 백업한 뒤 JMP 코드를 덮어씌워
// 안정적인 인라인 트램펄린(우회로)을 동적으로 생성 및 패치해야 한다.
// 특히 백업할 명령어 중에 RIP 상대 주소(PC-relative)를 사용하는 명령어가 포함되어 있으면
// 트램펄린이 할당된 메모리 위치에 맞춰 오프셋을 재계산해야 오류를 방지할 수 있다.
void build_trampoline()
{
    /*
       0x7f106f97fa00 <__strcmp_avx2>:      endbr64 
       0x7f106f97fa04 <__strcmp_avx2+4>:    mov    eax,edi
       0x7f106f97fa06 <__strcmp_avx2+6>:    xor    edx,edx
       0x7f106f97fa08 <__strcmp_avx2+8>:    vpxor  xmm7,xmm7,xmm7
       0x7f106f97fa0c <__strcmp_avx2+12>:   or     eax,esi
       0x7f106f97fa0e <__strcmp_avx2+14>:   and    eax,0xfff
       0x7f106f97fa13 <__strcmp_avx2+19>:   cmp    eax,0xf80
    */
    int safe_len = 14; // __strcmp_avx2의 완벽한 14바이트 경계
    //64비트 환경에서 점프를 위한 점프 명령어 바이트 템플릿
    unsigned char trampoline_template[14] = {
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00, //JMP QWORD PTR [RIP+0] (현재 명령어 바로 뒤에 있는 8바이트 값을 읽어서 거기로 점프해라)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 우리가 직접 채워 넣을 8바이트 절대 주소 공간
    };

    // mmap으로 트램펄린 공간 할당
    trampoline_addr = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (trampoline_addr == MAP_FAILED) {
        perror("mmap failed");
        return;
    }

    // 원본 14바이트 복사
    memcpy(trampoline_addr, original_strcmp, safe_len);

    // 돌아갈 주소 계산 및 JMP 조립 (64비트 절대주소 점프)
    long return_addr = (long)original_strcmp + safe_len;
    *(long*)(&trampoline_template[6]) = return_addr;

    // 복사한 14바이트 바로 뒤에 JMP 기계어 이어 붙이기
    memcpy((void*)((long)trampoline_addr + safe_len), trampoline_template, 14);
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
    printf("get pid\n");
    pid_t mypid = getpid();
    printf("get pid %d\n", mypid);
    printf("get base\n");
    program_base = get_base_sys(mypid, NULL);
    printf("get base fail\n");
    libc_base = get_base_sys(mypid, "libc.so.6");
    printf("[*] program_base: 0x%lx, libc_base: 0x%lx\n", program_base, libc_base);

    //쓰기 권한 변경
    unprotect_memory((long)original_strcmp);
    //트램펄린 생성
    build_trampoline();
    //변경할 훅 함수 주소
    long mystrcmp_addr = (long)mystrcmp;
    //64비트 환경에서 점프를 위한 점프 명령어 바이트 템플릿
    unsigned char hook_template[14] = {
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00, //JMP QWORD PTR [RIP+0] (현재 명령어 바로 뒤에 있는 8바이트 값을 읽어서 거기로 점프해라)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 우리가 직접 채워 넣을 8바이트 절대 주소 공간
    };

    //6번 인덱스에 훅 함수의 주소를 저장
    *(long*)(&hook_template[6])=mystrcmp_addr;
    //mprotect로 쓰기 권한을 얻은 공간에 overwrite
    memcpy((void*)original_strcmp, hook_template, 14);
    //쓰기권한 해제
    //protect_memory((long)original_strcmp);

    printf("[+] HOOK SETUP DONE!\n");
}

//라이브러리가 dlopne으로 로드되자 마자 '자동으로' 실행되는 초기화 함수
__attribute__((constructor))
void on_library_loaded(){
    // 밖에서 dlopne이 성공하는 즉시 이 코드가 자동으로 실행됨
    setup_hook();
}