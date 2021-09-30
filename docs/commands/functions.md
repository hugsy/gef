## Command functions ##

The `functions` command will list all of
the [convenience functions](https://sourceware.org/gdb/onlinedocs/gdb/Convenience-Funs.html)
provided by GEF.

- `$_base([filepath])`    -- Return the matching file's base address plus an
  optional offset. Defaults to the current file. Note that quotes need to be
  escaped.
- `$_bss([offset])`       -- Return the current bss base address plus the given
  offset.
- `$_got([offset])`       -- Return the current bss base address plus the given
  offset.
- `$_heap([offset])`      -- Return the current heap base address plus an
  optional offset.
- `$_stack([offset])`     -- Return the current stack base address plus an
  optional offset.

These functions can be used as arguments to other commands to dynamically
calculate values.

```
gef➤  deref -l 4 $_heap()
0x0000000000602000│+0x00: 0x0000000000000000	 ← $r8
0x0000000000602008│+0x08: 0x0000000000000021 ("!"?)
0x0000000000602010│+0x10: 0x0000000000000000	 ← $rax, $rdx
0x0000000000602018│+0x18: 0x0000000000000000
gef➤  deref -l 4 $_heap(0x20)
0x0000000000602020│+0x00: 0x0000000000000000	 ← $rsi
0x0000000000602028│+0x08: 0x0000000000020fe1
0x0000000000602030│+0x10: 0x0000000000000000
0x0000000000602038│+0x18: 0x0000000000000000
gef➤  deref -l 4 $_base(\"libc\")
0x00007ffff7da9000│+0x0000: 0x03010102464c457f
0x00007ffff7da9008│+0x0008: 0x0000000000000000
0x00007ffff7da9010│+0x0010: 0x00000001003e0003
0x00007ffff7da9018│+0x0018: 0x0000000000027c60
```
