/**
 * default.c
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char msg[0x100];

int main(int argc, char** argv, char** envp)
{
        strncpy(msg, "Hello world!", sizeof(msg));
        __asm__ volatile("int3;" : : : );
        return EXIT_SUCCESS;
}
