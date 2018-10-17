/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 *
 * heap-analysis.c
 *
 * @author: @Grazfather
 * @licence: WTFPL v.2
 */

#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{
        void* p1 = malloc(0x10);
        void* p2 = calloc(0x20, 1);
        memset(p1, 'A', 0x10);
        memset(p2, 'B', 0x20);
        p1 = realloc(p1, 0x30);
        free(p2);
        return EXIT_SUCCESS;
}
