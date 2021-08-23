## Command name-break ##

The command `name-break` (alias `nb`) can be used to set a breakpoint on
a location with a name assigned to it.

Every time this breakpoint is hit, the specified name will also be shown
in the `extra` section to make it easier to keep an overview when using
multiple breakpoints in a stripped binary.

`name-break name [address]`

`address` may be a linespec, address, or explicit location, same as specified
for `break`. If `address` isn't specified, it will create the breakpoint at the
current instruction pointer address.

Examples:

- `nb first *0x400ec0`
- `nb "main func" main`
- `nb read_secret *main+149`
- `nb check_heap`

Example output:

```
─────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400e04                  add    eax, 0xfffbe6e8
     0x400e09                  dec    ecx
     0x400e0b                  ret
 →   0x400e0c                  push   rbp
     0x400e0d                  mov    rbp, rsp
     0x400e10                  sub    rsp, 0x50
     0x400e14                  mov    QWORD PTR [rbp-0x48], rdi
     0x400e18                  mov    QWORD PTR [rbp-0x50], rsi
     0x400e1c                  mov    rax, QWORD PTR fs:0x28
───────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe288│+0x0000: 0x0000000000401117  →   movzx ecx, al	 ← $rsp
0x00007fffffffe290│+0x0008: 0x00007fffffffe4b8  →  0x00007fffffffe71d  →  "/ctf/t19/srv_copy"
0x00007fffffffe298│+0x0010: 0x0000000100000000
0x00007fffffffe2a0│+0x0018: 0x0000000000000000
0x00007fffffffe2a8│+0x0020: 0x0000000000000004
0x00007fffffffe2b0│+0x0028: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────── extra ────
[+] Hit breakpoint *0x400e0c (check_entry)
────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
