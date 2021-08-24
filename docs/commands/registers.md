## Command registers ##

The `registers` command will print all the registers and dereference any
pointers.

Example on a MIPS host:

```
gef➤ reg
$zero     : 0x00000000
$at       : 0x00000001
$v0       : 0x7fff6cd8 -> 0x77e5e7f8 -> <__libc_start_main+200>: bnez v0,0x77e5e8a8
$v1       : 0x77ff4490
$a0       : 0x00000001
$a1       : 0x7fff6d94 -> 0x7fff6e85 -> "/root/demo-mips"
$a2       : 0x7fff6d9c -> 0x7fff6e91 -> "SHELL=/bin/bash"
$a3       : 0x00000000
$t0       : 0x77fc26a0 -> 0x0
$t1       : 0x77fc26a0 -> 0x0
$t2       : 0x77fe5000 -> "_dl_fini"
$t3       : 0x77fe5000 -> "_dl_fini"
$t4       : 0xf0000000
$t5       : 0x00000070
$t6       : 0x00000020
$t7       : 0x7fff6bc8 -> 0x0
$s0       : 0x00000000
$s1       : 0x00000000
$s2       : 0x00000000
$s3       : 0x00500000
$s4       : 0x00522f48
$s5       : 0x00522608
$s6       : 0x00000000
$s7       : 0x00000000
$t8       : 0x0000000b
$t9       : 0x004008b0 -> <main>: addiu sp,sp,-32
$k0       : 0x00000000
$k1       : 0x00000000
$s8       : 0x00000000
$status   : 0x0000a413
$badvaddr : 0x77e7a874 -> <__cxa_atexit>: lui gp,0x15
$cause    : 0x10800024
$pc       : 0x004008c4 -> <main+20>: li v0,2
$sp       : 0x7fff6ca0 -> 0x77e4a834 -> 0x29bd
$hi       : 0x000001a5
$lo       : 0x00005e17
$fir      : 0x00739300
$fcsr     : 0x00000000
$ra       : 0x77e5e834 -> <__libc_start_main+260>: lw gp,16(sp)
$gp       : 0x00418b20
```

### Filtering registers ###

If one or more register names are passed to the `registers` command as optional
arguments, then only those will be shown:

```
gef➤ reg $rax $rip $rsp
$rax   : 0x0000555555555169  →  <main+0> endbr64
$rsp   : 0x00007fffffffe3e8  →  0x00007ffff7df40b3  →  <__libc_start_main+243> mov edi, eax
$rip   : 0x0000555555555169  →  <main+0> endbr64
```
