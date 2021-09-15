/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 *
 * heap-fastbins.c
 *
 * @author: @_hugsy_
 * @licence: WTFPL v.2
 *
 * to test the fastbins the tcache has to be disabled through the environment in GDB:
 * `set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0`
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int main()
{
    void* p1 = malloc(0x10);
    void* p2 = malloc(0x20);
    void* p3 = malloc(0x30);
    memset(p1, 'A', 0x10);
    memset(p2, 'B', 0x20);
    memset(p3, 'C', 0x30);
    free(p2);
    DebugBreak();
    (void)p1;
    (void)p3;
    return EXIT_SUCCESS;
}
