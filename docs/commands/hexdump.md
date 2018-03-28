## Command hexdump ##

Imitation of the WinDBG command.

This command requires at least 2 arguments, the format for representing the
data, and a value/address/symbol used as the location to print the hexdump
from. An optional 3rd argument is used to specify the number of
qword/dword/word/bytes to display.

The command provides WinDBG compatible aliases by default:

  - `hexdump qword` -> `dq`
  - `hexdump dword` -> `dd`
  - `hexdump word` -> `dw`
  - `hexdump byte` -> `db`

`hexdump byte` will also try to display the ASCII character values if the byte
is printable (similarly to the `hexdump -C` command on Linux).

The syntax is as following:

```
hexdump (qword|dword|word|byte) LOCATION L[SIZE] [UP|DOWN]
```

Examples:

   * Display 4 QWORD from `$pc`:

```
gef➤  dq $pc l4
0x7ffff7a5c1c0+0000 │ 0x4855544155415641
0x7ffff7a5c1c0+0008 │ 0x0090ec814853cd89
0x7ffff7a5c1c0+0010 │ 0x377d6f058b480000
0x7ffff7a5c1c0+0018 │ 0x748918247c894800
```

  * Display 32 bytes from a location in the stack:

```
gef➤  db 0x00007fffffffe5e5 l32
0x00007fffffffe5e5     2f 68 6f 6d 65 2f 68 75 67 73 79 2f 63 6f 64 65     /home/hugsy/code
0x00007fffffffe5f5     2f 67 65 66 2f 74 65 73 74 73 2f 77 69 6e 00 41     /gef/tests/win.A
```
