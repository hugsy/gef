#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "utils.h"

void *thread1(void *vargp)
{
    char* a = (char*) malloc(20);
    char* b = (char*) malloc(20);
    char* c = (char*) malloc(20);
    free(a);
    free(b);
    free(c);
    sleep(100);
    return NULL;
}

void *thread2(void *vargp)
{
    char* a = (char*) malloc(40);
    char* b = (char*) malloc(40);
    char* c = (char*) malloc(40);
    free(a);
    free(b);
    free(c);
    sleep(100);
    return NULL;
}

int main()
{
    pthread_t thread_id1, thread_id2;
    pthread_create(&thread_id1, NULL, thread1, NULL);
    pthread_create(&thread_id2, NULL, thread2, NULL);
    sleep(1);
    DebugBreak();
    exit(0);
}
