#ifndef MYUTIL_H
#define MYUTIL_H

#include <sys/types.h> // pid_t를 인식하기 위해 필요
long get_base_std(pid_t target_pid, const char* area);
long get_base_sys(pid_t target_pid, const char* area);
long get_libc_func_offset(const char* path, const char* func_name);

#endif