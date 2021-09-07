## Command hexdump ##

Imitation of the WinDBG command.

This command takes 4 optional arguments:

- The format for representing the data (by default, byte)
- A value/address/symbol used as the location to print the hexdump from (by
  default, $sp)
- The number of qword/dword/word/bytes to display (by default, 64 if the format
  is byte, 16 otherwise)
- The direction of output lines (by default, from low to high addresses)

`hexdump byte` will also try to display the ASCII character values if the byte
is printable (similarly to the `hexdump -C` command on Linux).

The syntax is as following:

```
hexdump (qword|dword|word|byte) [-h] [--reverse] [--size SIZE] [address]
```

Examples:

- Display 4 QWORDs from `$pc`:

```
gef➤  hexdump qword $pc --size 4
0x7ffff7a5c1c0+0000 │ 0x4855544155415641
0x7ffff7a5c1c0+0008 │ 0x0090ec814853cd89
0x7ffff7a5c1c0+0010 │ 0x377d6f058b480000
0x7ffff7a5c1c0+0018 │ 0x748918247c894800
```

- Display 32 bytes from a location in the stack:

```
gef➤  hexdump byte 0x00007fffffffe5e5 --size 32
0x00007fffffffe5e5     2f 68 6f 6d 65 2f 68 75 67 73 79 2f 63 6f 64 65     /home/hugsy/code
0x00007fffffffe5f5     2f 67 65 66 2f 74 65 73 74 73 2f 77 69 6e 00 41     /gef/tests/win.A
```

- Display 8 WORDs from `$sp` in reverse order:

```
gef➤  hexdump word 8 --reverse
0x00007fffffffe0ee│+0x000e   0x0000
0x00007fffffffe0ec│+0x000c   0x7fff
0x00007fffffffe0ea│+0x000a   0xffff
0x00007fffffffe0e8│+0x0008   0xe3f5
0x00007fffffffe0e6│+0x0006   0x0000
0x00007fffffffe0e4│+0x0004   0x0000
0x00007fffffffe0e2│+0x0002   0x0000
0x00007fffffffe0e0│+0x0000   0x0001
```
