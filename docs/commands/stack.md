## Command stack

The `stack` command will print the current stack frame and dereference any
pointers. It does not take any argument.

Example:
```
gef➤  stack
0x00007fffffffddb0│+0x0040: 0x0000000000000000   ← $rbp
0x00007fffffffdda8│+0x0038: 0x0000000000000000
0x00007fffffffdda0│+0x0030: 0x00007fffffffdea0  →  0x0000000000000001
0x00007fffffffdd98│+0x0028: 0x0000000000401050  →  <_start+0> endbr64 
0x00007fffffffdd90│+0x0020: 0x0000000000000000
0x00007fffffffdd88│+0x0018: 0x0000000000401170  →  <__libc_csu_init+0> endbr64 
0x00007fffffffdd80│+0x0010: 0x0000000000000000
0x00007fffffffdd78│+0x0008: 0x00000000004011bd  →  <__libc_csu_init+77> add rbx, 0x1
0x00007fffffffdd70│+0x0000: 0x0000000000000000   ← $rax, $rsp, $rdi
```
