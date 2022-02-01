/**
 * syscall-args.c
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>

#include "utils.h"

#define __NR_read 0

void openfile()
{
    int ret;
    size_t size = 256;
    char buf[256] = {0};
    int fd = openat(AT_FDCWD, "/etc/passwd", O_RDONLY);
    if(fd != -1){
        close(fd);
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386) || defined(i386) || defined(__i386__)
        __asm__ volatile
        (
#if defined(__i386) || defined(i386) || defined(__i386__)
            "int $0x80"
#else
            "syscall"
#endif
            : "=a" (ret)
            : "0"(__NR_read), "b"(fd), "c"(buf), "d"(size)
            : "memory"
        );
#else
        DebugBreak();
#endif
    }
}


int main(int argc, char** argv, char** envp)
{
    openfile();
    return EXIT_SUCCESS;
}
