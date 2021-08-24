## Command set-permission ##

This command was added to facilitate the exploitation process, by changing the
permissions on a specific memory page directly from the debugger.

By default, GDB does not allow you to do that, so the command will modify a
code section of the binary being debugged, and add a native `mprotect` syscall
stub. For example, for x86, the following stub will be inserted:

```
pushad
mov eax, mprotect_syscall_num
mov ebx, address_of_the_page
mov ecx, size_of_the_page
mov edx, permission_to_set
int 0x80
popad
```

A breakpoint is added following this stub, which when hit will restore the
original context, allowing you to resume execution.

The usage is

```
gef➤ set-permission address [permission]
```

The `permission` can be set using a bitmask as integer with read (1), write (2)
and execute (4). For combinations of these permissions they can just be added:
Read and Execute permission would be 1 + 4 = 5.

`mprotect` is an alias for `set-permission`. As an example, to set the `stack`
as READ|WRITE|EXECUTE on this binary,

![mprotect-before](https://i.imgur.com/RRYHxzW.png)

Simply run

```
gef➤ mprotect 0xfffdd000
```

Et voilà! GEF will use the memory runtime information to correctly adjust the
permissions of the entire section.

![mprotect-after](https://i.imgur.com/9MvyQi8.png)

Or for a full demo video on an AARCH64 VM:

[![set-permission-aarch64](https://img.youtube.com/vi/QqmfxIGzbmM/0.jpg)](https://www.youtube.com/watch?v=QqmfxIGzbmM)
