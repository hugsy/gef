/**
 * -*- mode: c -*-
 * -*- coding: utf-8 -*-
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "utils.h"

void *thread()
{
        void* p1 = malloc(0x18);
        void* p2 = malloc(0x18);
        free(p1);
        DebugBreak();
        (void)p2;

        return NULL;
}

int main(int argc, char** argv, char** envp)
{
        void* p1 = malloc(0x10);

        pthread_t thread1;
        pthread_create(&thread1, NULL, thread, NULL);
        pthread_join(thread1, NULL);

        (void)p1;
        return EXIT_SUCCESS;
}
