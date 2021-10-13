#include "utils.h"
void f10(){ DebugBreak(); }
void f9(){ f10(); }
void f8(){ f9(); }
void f7(){ f8(); }
void f6(){ f7(); }
void f5(){ f6(); }
void f4(){ f5(); }
void f3(){ f4(); }
void f2(){ f3(); }
void f1(){ f2(); }
int main(){ f1(); return 0;}