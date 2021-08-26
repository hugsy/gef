#include<stdio.h>
#include<stdlib.h>

int myglobal = 1;

int main(int argc, char** argv)
{
    // breakpoints hardcoded for convenience
    myglobal = strtoll(argv[1], NULL, 16);
    __builtin_trap();
    return 0;
}
