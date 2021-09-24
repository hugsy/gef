/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 *
 * set-permission.c
 *
 * @author: @_hugsy_
 * @licence: WTFPL v.2
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "utils.h"

int main(int argc, char** argv, char** envp)
{
        void *p = mmap((void *)0x1337000,
                       getpagesize(),
                       PROT_READ|PROT_WRITE,
                       MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,
                       -1,
                       0);

        if( p == (void *)-1)
                return EXIT_FAILURE;

        DebugBreak();

        return EXIT_SUCCESS;
}
