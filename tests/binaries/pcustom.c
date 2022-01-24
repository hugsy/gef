#include <stdio.h>
#include "utils.h"

struct foo_t {
    int a;
    int b;
};

struct goo_t {
    int a;
    int b;
    struct foo_t* c;
    int d;
    int e;
};

int main()
{
    struct foo_t f1 = {1, 2};
    struct goo_t g1 = {3, 4, &f1, 12, 13};
    printf("%p\n", &g1);
    DebugBreak();
    return 0;
}
