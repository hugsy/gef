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
#include "utils.h"

int main(int argc, char** argv, char** envp)
{
        void* p1 = malloc(0x20);
        DebugBreak();
        (void)p1;
        return EXIT_SUCCESS;
}
