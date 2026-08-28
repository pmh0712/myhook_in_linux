#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dlfcn.h>
#include "myutil.h"


// 문자열을 8바이트씩 쪼개서 타겟 메모리에 덮어쓰는 함수
void write_string_to_target(pid_t pid, long addr, const char *str){
    //문자열 끝을 알리는 NULL 바이트까지 포함해서 길이를 구함
    int len = strlen(str) + 1;
    int word_size = sizeof(long); //64비트 환경에서 8바이트

    for (int i = 0; i < len; i+=word_size){
        long word = 0;

        //str 배열에서 8바이트 만큼 떼어와서 word 변수에 복사
        //남은 길이가 8바이트보다 작으면 남은 만큼만 복사에서 쓰레기 값이 안들어가게 방지
        int copy_len = (len - i < word_size) ? (len - i) : word_size;
        memcpy(&word, str + i, copy_len);

        //타겟 프로세스의 (주소 + i) 위치에 딱 8바이트(word)를 밀어 넣음
        ptrace(PTRACE_POKETEXT, pid, addr+i, (void*)word);
    }
}

int main(int argc, char* argv[]){
    if (argc < 3){
        printf("Usage: %s [target PID] [hook path]\n", argv[0]);
        return 0;
    }

    pid_t target_pid = atoi(argv[1]);
    struct user_regs_struct original_regs, modified_regs;
    
    //1. 타겟 납치 및 정지
    printf("Attaching to process: %d\n", target_pid);
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0){
        perror("ptrace attach failed\n");
        return 1;
    }
    waitpid(target_pid, NULL, 0); //타겟이 완전히 멈출 때까지 대기

    //2. 주소 계산 및 원본 레지스터 백업
    long libc_base = get_base_std(target_pid, "libc.so");
    long dlopen_offset = get_libc_func_offset("/usr/lib/x86_64-linux-gnu/libc.so.6", "dlopen");
    long target_dlopen_addr = libc_base + dlopen_offset;

    // 타겟이 멈춘 시점의 CPU 레지스터 전체 상태를 안전하게 백업
    ptrace(PTRACE_GETREGS, target_pid, NULL, &original_regs);
    // 조작용 복사본 생성
    memcpy(&modified_regs, &original_regs, sizeof(struct user_regs_struct));

    //3. 메모리 변조 및 실행 흐름 조작
    //타겟 메모리의 빈 공간을 찾아 후킹 코드 경로 문자열을 PTRACE_POKETEXT로 쓴다.
    long free_memory_addr = original_regs.rsp - 2048; //스택 위쪽 빈 공간 사용
    write_string_to_target(target_pid, free_memory_addr, argv[2]);

    //타겟이 원래 실행 중이던 위치(RIP)의 기계어 8바이트를 읽어옴
    long original_code = ptrace(PTRACE_PEEKTEXT, target_pid, original_regs.rip, NULL);
    //그 자리 맨 앞 1바이트를 0xCC (INT 3 - 브레이크포인트)로 변조해서 덮어씀
    long trap_code = (original_code & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKETEXT, target_pid, original_regs.rip, (void*)trap_code);

    //dlopen을 위한 스택포인터 16배수 정렬
    long aligned_rsp = ((free_memory_addr - 16) & ~0xF) + 8;

    //돌아갈 주소를 방금 0xCC를 심어둔 원래 RIP(정상 주소)로 세팅!
    // dlopen은 정상적인 주소에서 호출한 줄 알고 속아서 성공하게 됨
    ptrace(PTRACE_POKEDATA, target_pid, (void*)aligned_rsp, (void*)original_regs.rip);

    //스택 16배수 정렬
    modified_regs.rsp = aligned_rsp;
    //x86_64 함수 호출 규약: 첫 번째 인자 (RDI)에 문자열 주소 삽입
    modified_regs.rdi = free_memory_addr;
    //x86_64 함수 호출 규약: 두 번째 인자 (RSI)에 flag값(2(RTLD_NOW)=적재하자 마자 바로 실행) 삽입
    modified_regs.rsi = 2;
    //RIP(다음 실행할 명령어 주소)를 dlopen의 주소로 변경
    modified_regs.rip = target_dlopen_addr;
    //커널의 Syscall 재시작(RIP - 2) 오지랖 방지(커널 스택에 있는 값)
    modified_regs.orig_rax = -1;
    //조작된 레지스터를 타겟 프로세스에 덮어쓰기
    ptrace(PTRACE_SETREGS, target_pid, NULL, &modified_regs);

    //4. 강제 실행 및 원상 복구
    printf("Executing dlopen...\n");
    //타깃 프로세스를 다시 실행시킴 (이때 dlopen이 호출)
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);

    //타겟이 dlopen 실행을 마치고 멈출 때까지 대기
    int status;
    waitpid(target_pid, &status, 0);

    // 타겟이 어떤 시그널을 받고 멈췄는지 출력
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        printf("[*] Target stopped with signal: %d\n", sig);
        if (sig == 11) {
            printf("[!!!!!] SIGSEGV (Segmentation Fault) detected! 스택 터짐 확정!\n");
        }
    }

    
    struct user_regs_struct check_regs;
    ptrace(PTRACE_GETREGS, target_pid, NULL, &check_regs);
    
    printf("[*] dlopen_addr : 0x%lx\n", target_dlopen_addr);
    printf("[*] RIP stopped at: 0x%llx\n", check_regs.rip);
    printf("[*] RAX (Return)  : 0x%llx\n", check_regs.rax);
   

    //0xCC로 오염시켰던 타겟의 기계어를 원본(original_code)으로 다시 복구
    ptrace(PTRACE_POKETEXT, target_pid, original_regs.rip, (void*)original_code);
    //백업해 두었던 원래 레지스터 상태로 완벽히 복구
    ptrace(PTRACE_SETREGS, target_pid, NULL, &original_regs);

    printf("Detaching...\n");
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    
    return 0;
}