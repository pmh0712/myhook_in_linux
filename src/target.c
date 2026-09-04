// target.c
#include <stdio.h>
#include <unistd.h>

// ---------------------------------------------------------
// [공통 타겟] Near Call 테스트용 외부 함수
// ---------------------------------------------------------
void dummy_target_func() {
    printf("  [+] Dummy Call Executed!\n");
}

// RIP-relative 테스트를 위한 전역 변수
int global_dummy_data = 0x1337;


// ---------------------------------------------------------
// 1. RIP-relative Data (데이터 참조) 테스트
// ---------------------------------------------------------
// offset = 0x11c3
__attribute__((naked)) void test_rip_relative() {
    __asm__ volatile (
        "lea rax, [rip + global_dummy_data]\n" // 7바이트: RIP 상대 오프셋으로 주소 로드
        "mov eax, [rax]\n"                     // 2바이트
        "nop; nop; nop; nop; nop;\n"           // 패딩 (14바이트 넘기기용)
        "ret\n"
    );
}

// ---------------------------------------------------------
// 2. Short JMP (EB) 테스트 (2바이트 -> 5바이트 뻥튀기 타겟)
// ---------------------------------------------------------
// offset = 0x11d9
__attribute__((naked)) void test_short_jmp() {
    __asm__ volatile (
        "jmp 1f\n"                 // 2바이트: EB xx (거리가 짧아서 Short JMP로 컴파일 됨)
        "nop; nop; nop;\n"         // 3바이트
        "1:\n"                     
        "mov eax, 1\n"             
        "nop; nop; nop; nop;\n"    
        "ret\n"
    );
}

// ---------------------------------------------------------
// 3. Short JCC (7X) 테스트 (2바이트 -> 6바이트 뻥튀기 타겟)
// ---------------------------------------------------------
// offset = 0x11ef
__attribute__((naked)) void test_short_jcc() {
    __asm__ volatile (
        "xor rax, rax\n"           // 3바이트: 0으로 세팅 (Zero Flag 켜짐)
        "test rax, rax\n"          // 3바이트
        "jz 1f\n"                  // 2바이트: 74 xx (거리가 짧아서 Short JCC로 컴파일 됨)
        "nop; nop;\n"
        "1:\n"
        "mov eax, 2\n"
        "ret\n"
    );
}

// ---------------------------------------------------------
// 4. Near CALL (E8) 테스트 (그대로 32비트 변위 재계산)
// ---------------------------------------------------------
// offset = 0x1206
__attribute__((naked)) void test_near_call() {
    __asm__ volatile (
        "call dummy_target_func\n" // 5바이트: E8 xx xx xx xx (외부 함수 호출이므로 32비트 Near Call 사용)
        "mov eax, 3\n"             
        "nop; nop; nop; nop;\n"
        "ret\n"
    );
}

// ---------------------------------------------------------
// 5. Near JMP (E9) 테스트 (거리가 128바이트 이상이라 강제로 E9 생성)
// ---------------------------------------------------------
// offset = 0x121c
__attribute__((naked)) void test_near_jmp() {
    __asm__ volatile (
        "jmp 1f\n"                 // 거리가 멀어서 강제로 5바이트(E9 xx xx xx xx)로 컴파일 됨
        ".space 200, 0x90\n"       // ★ 핵심: NOP(0x90) 200바이트를 쑤셔넣어서 Short 범위를 초과시킴
        "1:\n"                     
        "mov eax, 4\n"
        "ret\n"
    );
}

// ---------------------------------------------------------
// 6. Near JCC (0F 8X) 테스트 (거리가 128바이트 이상이라 강제로 0F 8X 생성)
// ---------------------------------------------------------
// offset = 0x12f6
__attribute__((naked)) void test_near_jcc() {
    __asm__ volatile (
        "xor rax, rax\n"           
        "test rax, rax\n"          
        "jz 1f\n"                  // 거리가 멀어서 강제로 6바이트(0F 84 xx xx xx xx)로 컴파일 됨
        ".space 200, 0x90\n"       // ★ 핵심: NOP(0x90) 200바이트 패딩
        "1:\n"
        "mov eax, 5\n"
        "ret\n"
    );
}

int main() {
    printf("[*] Target running. PID: %d\n", getpid());
    while(1) {
        test_rip_relative();
        test_short_jmp();
        test_short_jcc();
        test_near_call();
        test_near_jmp();
        test_near_jcc();
        sleep(2);
    }
    return 0;
}