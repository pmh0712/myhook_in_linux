// target.c
#include <stdio.h>
#include <unistd.h>

// 전역 변수 (RIP 상대 주소 타겟)
int g_status_code = 0;          // mov 테스트용
char g_secret_msg[] = "test!!"; // lea 테스트용

void target_function() {
    // 1. mov 명령어 유도: 전역 변수에 값 대입 (mov DWORD PTR [rip+offset], 0x1337)
    g_status_code = 0x1337;

    // 2. lea 명령어 유도: 전역 문자열의 주소를 레지스터에 로드 (lea rax, [rip+offset])
    char* msg_ptr = g_secret_msg;

    printf("[Target] Status: 0x%x, Message: %s\n", g_status_code, msg_ptr);
}

int main() {
    printf("[*] Target running. PID: %d\n", getpid());
    while(1) {
        target_function();
        sleep(2);
    }
    return 0;
}