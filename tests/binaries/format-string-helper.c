/**
 * bof.c
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


void greetz(char* buf)
{
        char name[256] = {0,};
        strcpy(name, buf);
        printf("Hello");
        printf(name);
        printf("\n");
}


int main(int argc, char** argv, char** envp)
{
        if(argc < 2)
                return EXIT_FAILURE;

        greetz(argv[1]);
        return EXIT_SUCCESS;
}
