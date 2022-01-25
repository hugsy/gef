#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "utils.h"

__attribute__((packed)) struct foo_t {
    int a;
    int b;
};

__attribute__((packed)) struct goo_t {
    int a;
    int b;
    struct foo_t* c;
    int d;
    int e;
};

int main()
{
    void *p = mmap((void *)0x1337000, getpagesize(), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    if( p == (void *)-1)
        return EXIT_FAILURE;

    struct foo_t *f1 = (struct foo_t *)p;
    f1->a=1; f1->b=2;
    struct goo_t* g1 = (struct goo_t *)((char*)p + 0x100);
    g1->a=3; g1->b=4; g1->c=f1; g1->d=12; g1->e=13;
    DebugBreak();
    return 0;
}
