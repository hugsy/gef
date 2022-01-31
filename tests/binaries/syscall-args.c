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

void openfile()
{
    int fd = openat(AT_FDCWD, "/etc/passwd", O_RDONLY);
    if(fd != -1){
        close(fd);
        DebugBreak();
    }
}


int main(int argc, char** argv, char** envp)
{
    openfile();
    return EXIT_SUCCESS;
}
