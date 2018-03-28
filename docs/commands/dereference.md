## Command dereference

The `dereference` command (also aliased `telescope` for PEDA former users) aims
to simplify the dereferencing of an address in GDB to determine the content it
actually points to.

It is a useful convienence function to spare to process of manually tracking
values with successive `x/x` in GDB.

`dereference` takes one mandatory argument, an address (or symbol or register,
etc) to dereference:

```
gef➤  dereference $sp
0x00007fffffffe258│+0x00: 0x0000000000400489  →  hlt     ← $rsp
gef➤  telescope 0x7ffff7b9d8b9
0x00007ffff7b9d8b9│+0x00: 0x0068732f6e69622f ("/bin/sh"?)
```

It also optionally accepts a second argument, the number of consecutive
addresses to dereference (by default, `1`).

For example, if you want to dereference all the stack entries inside a function
context (on a 64bit architecture):

```
gef➤  p ($rbp - $rsp)/8
$3 = 4
gef➤  dereference $rsp 5
0x00007fffffffe170│+0x00: 0x0000000000400690  →  push r15        ← $rsp
0x00007fffffffe178│+0x08: 0x0000000000400460  →  xor ebp, ebp
0x00007fffffffe180│+0x10: 0x00007fffffffe270  →  0x1
0x00007fffffffe188│+0x18: 0x1
0x00007fffffffe190│+0x20: 0x0000000000400690  →  push r15        ← $rbp
```
