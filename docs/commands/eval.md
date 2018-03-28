## Command $ ##

The `$` command attempts to mimic WinDBG `?` command.

When provided one argument, it will evaluate the expression, and try to display
the result with various formats:

```
gef➤  $ $pc+1
93824992252977
0x555555559431
0b10101010101010101010101010101011001010000110001
b'UUUU\x941'
b'1\x94UUUU'

gef➤  $ -0x1000
-4096
0xfffffffffffff000
0b1111111111111111111111111111111111111111111111111111000000000000
b'\xff\xff\xff\xff\xff\xff\xf0\x00'
b'\x00\xf0\xff\xff\xff\xff\xff\xff'
```

With two arguments, it will simply compute the delta between them:

```
gef➤  vmmap libc
Start              End                Offset             Perm
0x00007ffff7812000 0x00007ffff79a7000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff79a7000 0x00007ffff7ba7000 0x0000000000195000 --- /lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7ba7000 0x00007ffff7bab000 0x0000000000195000 r-- /lib/x86_64-linux-gnu/libc-2.24.so
0x00007ffff7bab000 0x00007ffff7bad000 0x0000000000199000 rw- /lib/x86_64-linux-gnu/libc-2.24.so

gef➤  $ 0x00007ffff7812000 0x00007ffff79a7000
-1658880
1658880

gef➤  $ 1658880
1658880
0x195000
0b110010101000000000000
b'\x19P\x00'
b'\x00P\x19'
```
