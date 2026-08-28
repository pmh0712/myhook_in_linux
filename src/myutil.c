#include "myutil.h"
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

long get_base_std(pid_t target_pid, const char* area)
{
    char map_path[256];
    char line[512];
    char search_str[512];
    long base_addr = 0;

    //인자기 NULL로 들어오면 메인 프로그램(기본값)
    if (area == NULL){
        // /proc/pid/exe는 프로그램의 메인 실행파일의 절대경로를 저장하는 심볼릭 링크
        char exe_link[256];
        snprintf(exe_link, sizeof(exe_link),"/proc/%d/exe", target_pid);

        //readlink를 통해 커널에서 메인 프로그램의 절대경로 획득
        ssize_t len = readlink(exe_link, search_str, sizeof(search_str) - 1);
        if(len != -1){
            search_str[len] = '\0';
            printf("get_path! %s\n", search_str);
        }
        else{
            printf("readlink failed!\n");
            return 0;
        }

    }
    else{
        strncpy(search_str, area, sizeof(search_str));
    }

    //maps 이용하여 메모리 베이스 찾기
    snprintf(map_path, sizeof(map_path), "/proc/%d/maps", target_pid);
    FILE *fp = fopen(map_path, "r");
    if (!fp) {
        printf("fopen failed!");
        return 0;

    }

    while (fgets(line, sizeof(line), fp)){
        if (strstr(line, search_str)){
            sscanf(line, "%lx-", &base_addr);
            break;
        }

    }
    fclose(fp);
    return base_addr;
}

//인젝션 환경의 불안정성으로 인한 데드락과 라이브러리 간 충돌을 방지용
//커널을 이용해 라이브러리 우회
long get_base_sys(pid_t target_pid, const char* area)
{
    //인젝션 환경의 스택을 보호하기 위해 static 사용하여 bss활용
    static char map_path[256];
    static char exe_link[256];
    static char search_str[512];
    static char buffer[0x4000];
    long base_addr = 0;

    // static 특성상 이전 호출의 쓰레기 값이 남아 있을 수 있으므로 초기화
    memset(search_str, 0, sizeof(search_str));
    memset(buffer, 0, sizeof(buffer));

    //인자기 NULL로 들어오면 메인 프로그램(기본값)
    if (area == NULL){
        snprintf(exe_link, sizeof(exe_link),"/proc/%d/exe", target_pid);
        // libc readlink 래퍼 대신 시스템 콜 직접호출
        ssize_t len = syscall(SYS_readlink, exe_link, search_str, sizeof(search_str) - 1);
        if (len > 0){
            search_str[len] = '\0';
        }
        else{
            return 0;
        }

    }
    else{
        strncpy(search_str, area, sizeof(search_str));
        search_str[sizeof(search_str) - 1] = '\0';
    }

    snprintf(map_path, sizeof(map_path), "/proc/%d/maps", target_pid);
    
    // libc open 래퍼 대신에 시스템 콜 직접 호출
    int fd = syscall(SYS_open, map_path, O_RDONLY);
    if (fd < 0){
        return 0;
    }

    // 인젝션 중 정지를 위해 libc(read)에 삽입한 0xCC(INT 3)을 회피하기 위해 커널을 사용
    ssize_t total_read = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);

    // close도 시스템 콜로 처리
    syscall(SYS_close, fd);

    if (total_read > 0){
        buffer[total_read] = '\0';

        // strtok을 이용해 줄 단위로 파싱 후 strstr로 비교
        char *saveptr;
        char *token = strtok_r(buffer, "\n", &saveptr);
        while (token != NULL){
            if (strstr(token, search_str)){
                sscanf(token, "%lx-", &base_addr);
                break;
            }
            token = strtok_r(NULL, "\n", &saveptr);
        }
    }
    return base_addr;
}

long get_libc_func_offset(const char* path, const char* func_name){
    FILE *fp =  fopen(path, "rb");

    //1. ELF 헤더 읽기 
    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(Elf64_Ehdr), fp);

    //2. 섹션 헤더 테이블 위치로 커서(파일포인터) 이동
    fseek(fp, ehdr.e_shoff, SEEK_SET);
    
    //3. 섹션 헤더 하나씩 읽기, 심볼테이블 위치와 스트링테이블 위치 찾기 
    Elf64_Shdr shdr;
    Elf64_Shdr dynstr_shdr;
    int found_dynsym = 0;

    for (int i = 0; i < ehdr.e_shnum; i++){
        fread(&shdr, 1, sizeof(Elf64_Shdr), fp);
        if (shdr.sh_type == SHT_DYNSYM){
            found_dynsym=1;
            break;
        }
    }

    if (found_dynsym == 0){
        fclose(fp);
        return 0;
    }

    //sh_link 이용해서, dynsym과 연결된 dynstr 찾기
    fseek(fp, ehdr.e_shoff+shdr.sh_link*sizeof(Elf64_Shdr), SEEK_SET);
    fread(&dynstr_shdr, 1, sizeof(Elf64_Shdr), fp);

    //심볼테이블로 점프
    fseek(fp, shdr.sh_offset, SEEK_SET);

    //4. 심볼테이블에서 원하는 함수 찾기
    Elf64_Sym sym;
    int count = (shdr.sh_size/sizeof(Elf64_Sym));
    for(int i = 0; i < count; i++){
        fread(&sym, 1, sizeof(Elf64_Sym), fp);
        //0이면 찾는 함수가 아니므로 패스
        if (sym.st_name == 0) continue;

        //현재 위치 저장(백업)
        long save_pos = ftell(fp);
        //함수 이름 비교를 위해 dynstr로 점프
        fseek(fp, dynstr_shdr.sh_offset + sym.st_name, SEEK_SET);

        //함수 이름 읽어오기
        char sym_name[256];
        fgets(sym_name, sizeof(sym_name), fp);

        //다시 심볼테이블로 복구
        fseek(fp, save_pos, SEEK_SET);

        //비교하여 같은 함수임을 확인하고 오프셋 반환
        if(strcmp(sym_name, func_name)==0){
            fclose(fp);
            return sym.st_value;
        }
    }
    fclose(fp);
    return 0;
}