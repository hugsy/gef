/**
 * default.c
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"

char msg[0x100];

int main(int argc, char** argv, char** envp)
{
        strncpy(msg, "Hello world!", sizeof(msg));
        DebugBreak();
        return EXIT_SUCCESS;
}
