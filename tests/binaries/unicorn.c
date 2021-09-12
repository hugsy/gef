#include <stdlib.h>
#include <string.h>

int function1()
{
    const char* a1 = "PATH";
    const char* a2 = "WHATEVER";
    return strcmp( getenv(a1), a2);
}

int main()
{
    return function1();
}