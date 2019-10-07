## Command functions ##

The `functions` command will list all of the [convenience functions](https://sourceware.org/gdb/onlinedocs/gdb/Convenience-Funs.html) provided by GEF.

* `$_base(name=current_file)`     -- Return the base address of the matching section (default current file).
* `$_bss(offset=0)`    -- Return the current bss base address plus the given offset.
* `$_got(offset=0)`    -- Return the current bss base address plus the given offset.
* `$_heap(offset=0)`   -- Return the current heap base address plus an optional offset.
* `$_stack(offset=0)`  -- Return the current stack base address plus an optional offset.


These functions can be used as arguments to other commands to dynamically calculate values.

```
gef➤  deref $_heap() l4
0x0000000000602000│+0x00: 0x0000000000000000	 ← $r8
0x0000000000602008│+0x08: 0x0000000000000021 ("!"?)
0x0000000000602010│+0x10: 0x0000000000000000	 ← $rax, $rdx
0x0000000000602018│+0x18: 0x0000000000000000
gef➤  deref $_heap(0x20) l4
0x0000000000602020│+0x00: 0x0000000000000000	 ← $rsi
0x0000000000602028│+0x08: 0x0000000000020fe1
0x0000000000602030│+0x10: 0x0000000000000000
0x0000000000602038│+0x18: 0x0000000000000000
```
