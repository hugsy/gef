/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 *
 * heap.c
 *
 * @author: @_hugsy_
 * @licence: WTFPL v.2
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{
        void* p1 = malloc(0x10);
        void* p2 = malloc(0x20);
        void* p3 = malloc(0x30);
        memset(p1, 'A', 0x10);
        memset(p2, 'B', 0x20);
        memset(p3, 'C', 0x30);
        free(p2);
        __asm__ volatile("int3;");
        (void)p1;
        (void)p3;
        return EXIT_SUCCESS;
}
