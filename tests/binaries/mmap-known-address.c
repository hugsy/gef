/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 *
 * mmap-known-address.c : only mmap() at 0x1337000 and DebugBreak
 *
 * @author: @_hugsy_
 * @licence: WTFPL v.2
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#include "utils.h"

int main(int argc, char **argv, char **envp)
{
    const size_t pgsz = getpagesize();

    void *a1 = mmap((void *)0x1337000,
            pgsz,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
            -1,
            0);

    if (a1 == (void *)-1)
        return EXIT_FAILURE;

    memset(a1, 0x41, pgsz);

    void *a2 = mmap((void *)0x2337000,
                    pgsz,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                    -1,
                    0);
    if (a2 == (void *)-1)
        return EXIT_FAILURE;

    memset(a2, 0xcc, pgsz);

    DebugBreak();

    return EXIT_SUCCESS;
}
