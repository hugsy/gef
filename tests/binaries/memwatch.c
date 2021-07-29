#include<stdio.h>

int myglobal = 1;

int main() {
    // breakpoints hardcoded for convenience
    asm("int3");
    scanf("%d", &myglobal);
    asm("int3");
    return 0;
}
