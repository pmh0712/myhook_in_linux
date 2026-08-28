#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

//원본 strcmp 함수 주소를 저장할 포인터
int (*original_strcmp)(const char*, const char*) = NULL;

//우리가 덮어씌울 가짜 strcmp 함수
int strcmp(const char *s1, const char *s2){
    //최초 실행 시, 메모리에서 진짜 strcmp의 주소를 찾아 저장해둠
    if (original_strcmp == NULL){
        original_strcmp = dlsym(RTLD_NEXT, "strcmp");
    } 

    printf("HACKED! \"%s\" vs \"%s\"\n", s1, s2);

    //무조건 0을 반환
    return 0;
}