#include<stdio.h>

int myglobal = 1;

int main()
{
    // breakpoints hardcoded for convenience
    scanf("%d", &myglobal);
    asm("int3");
    return 0;
}
