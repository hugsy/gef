#include "utils.h"
int f1(int i){ if(i==10) {DebugBreak(); return 0;} return f1(++i); }
int main(){ return f1(0); }