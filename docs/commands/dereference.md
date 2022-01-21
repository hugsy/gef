## Command dereference

The `dereference` command (also aliased `telescope` for PEDA former users) aims
to simplify the dereferencing of an address in GDB to determine the content it
actually points to.

It is a useful convienence function to spare to process of manually tracking
values with successive `x/x` in GDB.

`dereference` takes three optional arguments, a start address (or symbol or
register, etc) to dereference (by default, `$sp`), the number of consecutive
addresses to dereference (by default, `10`) and the base location for offset
calculation (by default the same as the start address):

```
gef➤  dereference
0x00007fffffffdec0│+0x0000: 0x00007ffff7ffe190  →  0x0000555555554000  →   jg 0x555555554047	 ← $rsp, $r13
0x00007fffffffdec8│+0x0008: 0x00007ffff7ffe730  →  0x00007ffff7fd3000  →  0x00010102464c457f
0x00007fffffffded0│+0x0010: 0x00007ffff7faa000  →  0x00007ffff7de9000  →  0x03010102464c457f
0x00007fffffffded8│+0x0018: 0x00007ffff7ffd9f0  →  0x00007ffff7fd5000  →  0x00010102464c457f
0x00007fffffffdee0│+0x0020: 0x00007fffffffdee0  →  [loop detected]
0x00007fffffffdee8│+0x0028: 0x00007fffffffdee0  →  0x00007fffffffdee0  →  [loop detected]
0x00007fffffffdef0│+0x0030: 0x00000000f7fa57e3
0x00007fffffffdef8│+0x0038: 0x0000555555755d60  →  0x0000555555554a40  →   cmp BYTE PTR [rip+0x201601], 0x0        # 0x555555756048
0x00007fffffffdf00│+0x0040: 0x0000000000000004
0x00007fffffffdf08│+0x0048: 0x0000000000000001
```

Here is an example with arguments:

```
gef➤  telescope $rbp+0x10 -l 8
0x00007fffffffdf40│+0x0000: 0x00007ffff7fa5760  →  0x00000000fbad2887
0x00007fffffffdf48│+0x0008: 0x00000001f7e65b63
0x00007fffffffdf50│+0x0010: 0x0000000000000004
0x00007fffffffdf58│+0x0018: 0x0000000000000000
0x00007fffffffdf60│+0x0020: 0x00007fffffffdfa0  →  0x0000555555554fd0  →   push r15
0x00007fffffffdf68│+0x0028: 0x0000555555554980  →   xor ebp, ebp
0x00007fffffffdf70│+0x0030: 0x00007fffffffe080  →  0x0000000000000001
0x00007fffffffdf78│+0x0038: 0x0000000000000000
```

It also optionally accepts a second argument, the number of consecutive
addresses to dereference (by default, `10`).

For example, if you want to dereference all the stack entries inside a function
context (on a 64bit architecture):

```
gef➤  p ($rbp - $rsp)/8
$3 = 4
gef➤  dereference -l 5
0x00007fffffffe170│+0x0000: 0x0000000000400690  →  push r15        ← $rsp
0x00007fffffffe178│+0x0008: 0x0000000000400460  →  xor ebp, ebp
0x00007fffffffe180│+0x0010: 0x00007fffffffe270  →  0x1
0x00007fffffffe188│+0x0018: 0x1
0x00007fffffffe190│+0x0020: 0x0000000000400690  →  push r15        ← $rbp
```

It is possible to change the offset calculation to use a different address than
the start address:

```
gef➤  dereference $sp -l 7 -r $rbp
0x00007ffe6ddaa3e0│-0x0030: 0x0000000000000000    ← $rsp
0x00007ffe6ddaa3e8│-0x0028: 0x0000000000400970  →  <__libc_csu_init+0> push r15
0x00007ffe6ddaa3f0│-0x0020: 0x0000000000000000
0x00007ffe6ddaa3f8│-0x0018: 0x00000000004006e0  →  <_start+0> xor ebp, ebp
0x00007ffe6ddaa400│-0x0010: 0x00007ffe6ddaa500  →  0x0000000000000001
0x00007ffe6ddaa408│-0x0008: 0xa42456b3ee465800
0x00007ffe6ddaa410│+0x0000: 0x0000000000000000    ← $rbp
```
