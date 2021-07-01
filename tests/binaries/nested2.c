int f1(int i){ if(i==10) {__asm__("int3"); return 0;} return f1(++i); }
int main(){ return f1(0); }