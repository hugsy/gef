# Features

This page will explain in details some non-trivial commands available in `GEF`
with examples and screenshots to make it easier to reproduce.

## `context` command
![gef-x86](https://pbs.twimg.com/media/BvdRAJKIUAA8R6_.png:large)


`GEF` (not unlike `PEDA` or `fG! famous gdbinit`) provides comprehensive context
menu when hitting a breakpoint.

* The register context box displays current register values. Values in red
  indicate that this register has its value changed since the last
  breakpoint. It makes it convenient to track values. Register values can be
  also accessed and/or dereferenced through the `reg` command.

* The stack context box shows the 10 (by default but can be tweaked) entries in
  memory pointed by the stack pointer register. If those values are pointers,
  they are successively dereferenced.

* The code context box shows the 10 (by default but can be tweaked) next
  instructions to be executed.


## `entry-break` command

The `entry-break` goal is to find and break at the most obvious entry point
available in the binary. Since the binary will start running, some of the `PLT`
entries will also be solved, making easier further debugging.

It will perform the following actions:

   1. Look up a `main` symbol. If found, set a temporary breakpoint and go;
   2. Otherwise, it will look up for `__libc_start_main`. If found, set a
   temporary breakpoint and go;
   3. Last case, it will get the entry point from the ELF header, set a
   breakpoint and run. This case should never fail if the ELF binary has a valid
   structure.

![entry-break-example](https://i.imgur.com/zXSERMh.png)


## `patch` command

The `patch` command allows to easily bypass a call or syscall. The syntax is as
following:

```
gef> patch [-r VALUE] [-p] [-h] [LOCATION]
```

`LOCATION` indicates the instruction to bypass. If none specified, it will use
the current value of the program counter. `patch` will overwrite the whole
instruction with `nop` (or equivalent, depending on the architecture).

If `-r <integer>` option is entered, it will also set the return register to the
value specified.

For example, it is trivial to bypass `fork()` calls. And setting option `-r 0`
will drop us into the "child" process. It must be noted that this is a different
behaviour from the classic `set follow-fork-mode child` since here we do not
spawn a new process.

The `-p` option makes the modification permanent accross executions. This is
perform using specific type of breakpoint.

__*Note*__: the permanent option only works for calls (whereas the temporary
option works for any instruction).

Example:

Patching `fork()` calls:

   * Before `patch`
![before-patch](https://i.imgur.com/Gr5g45S.png)

   * Apply `patch` and force return register to `0`
```
gef> patch -r 0 0x400596
```
![apply-patch](https://i.imgur.com/hYE2sv2.png)

   * After `patch`
![after-patch](https://i.imgur.com/iEZVJWb.png)


## `xinfo`/`vmmap`/`xfiles` commands

`xinfo`, `vmmap` and `xfiles` display a comprehensive and human-friendly memory
mapping of either the process or a specific location.

![vmmap-example](https://i.imgur.com/iau8SwS.png)

Interestingly, it helps finding secret gems: as an aware reader might have seen,
memory mapping differs from one architecture to another (this is one of the main
reasons I started `GEF` in a first place). For example, you can learn that
ELF running on SPARC architectures always have their `.data` and `heap` sections set as
Read/Write/Execute.

![xinfo-example](https://pbs.twimg.com/media/CCSW9JkW4AAx8gD.png:large)


## `heap` command

`heap` command provides information on the heap chunk specified as argument. For
the moment, it only supports GlibC heap format (see
[this link](http://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)
for  `malloc` structure information). Syntax is pretty straight forward

```
gef> heap [LOCATION]
```

will display information like this

![heap-example](https://i.imgur.com/xPcnzWp.png)

## `shellcode` command

`shellcode` is a command line client for @JonathanSalwan shellcodes database. It
can be used to search and download directly via `GEF` the shellcode you're
looking for. Two primitive subcommands are available, `search` and `get`

```
gef> shellcode search arm
[+] Showing matching shellcodes
901     Linux/ARM       Add map in /etc/hosts file - 79 bytes
853     Linux/ARM       chmod("/etc/passwd", 0777) - 39 bytes
854     Linux/ARM       creat("/root/pwned", 0777) - 39 bytes
855     Linux/ARM       execve("/bin/sh", [], [0 vars]) - 35 bytes
729     Linux/ARM       Bind Connect UDP Port 68
730     Linux/ARM       Bindshell port 0x1337
[...]
gef> shellcode get 698
[+] Downloading shellcode id=698
[+] Shellcode written as '/tmp/sc-EfcWtM.txt'
gef> system cat /tmp/sc-EfcWtM.txt
/*
Title:     Linux/ARM - execve("/bin/sh", [0], [0 vars]) - 27 bytes
Date:      2010-09-05
Tested on: ARM926EJ-S rev 5 (v5l)
Author:    Jonathan Salwan - twitter: @jonathansalwan

shell-storm.org

Shellcode ARM without 0x20, 0x0a and 0x00
[...]
```

## `format-string-helper` command

`format-string-helper` command will create a `GEF` specific type of breakpoints
dedicated to detecting potentially insecure format string when using the GlibC
library.

It will use this new breakpoint against several targets, including:

   * `printf()`
   * `sprintf()`
   * `fprintf()`
   * `snprintf()`
   * `vsnprintf()`

Just call the command to enable this functionality. `fmtstr-helper` is an alias of `format-string-helper`.
```
gef> fmtstr-helper
```

Then start the binary execution.
```
gef> g
```

If a potentially insecure entry is found, the breakpoint will trigger, stop the
process execution, display the reason for trigger and the associated context.

![fmtstr-helper-example](https://i.imgur.com/INU3KGn.png)


## `gef-remote` debugging

It is possible to use `gef` in a remote debugging environment.


### With a local copy

If you want to remotely debug a binary that you already have, you simply need to
specify to `gdb` where to find the debug information.

For example, if we want to debug `uname`, we do on the server:
```
$ gdbserver 0.0.0.0:1234 /bin/uname
Process /bin/uname created; pid = 32280
Listening on port 1234
```

And on the client, simply run `gdb`:
```
$ gdb /bin/uname
gef> target remote 192.168.56.1:1234
Process /bin/uname created; pid = 10851
Listening on port 1234
```
Or
```
$ gdb
gef> file /bin/uname
gef> target remote 192.168.56.1:1234
```


### Without a local copy

It is possible to use `gdb` internal functions to copy our targeted binary.

In the following of our previous, if we want to debug `uname`, run `gdb` and
connect to our `gdbserver`. To be able to locate the right process in the `/proc` 
structure, the command `gef-remote` requires 2 arguments:
   - `-t` to provide the target host and port
   - `-p` to provide the PID on the remote host

```
$ gdb
gef> gef-remote -t 192.168.56.1:1234 -p 10851
[+] Connected to '192.168.56.1:1234'
[+] Downloading remote information
[+] Remote information loaded, remember to clean '/tmp/10851' when your session is over

```

As you can observe, if it cannot find the debug information, `gef` will try to download
automatically the target file and store in the local temporary directory (on
most Unix `/tmp`). If successful, it will then automatically load the debug
information to `gdb` and proceed with the debugging.

![gef-remote-autodownload](https://i.imgur.com/S3X536b.png)

You can then reuse the downloaded file for your future debugging sessions, use it under IDA 
and such. This makes the entire remote debugging process (particularly for Android applications) 
a child game.


## `capstone-disassemble` command

If you have installed [`capstone`](http://capstone-engine.org) library and its
Python bindings, you can use it to disassemble any location in your debugging
session. This plugin was done to offer an alternative to `GDB` disassemble
function which sometimes gets things mixed up :)

You can use its alias `cs-disassemble` and the location to disassemble (if not
specified, it will use `$pc`).

```
gef> cs main
```

![cs-disassemble](https://i.imgur.com/wypt7Fo.png)


## `set-permission` command

This command was added to facilitate the exploitation process, by changing the
permission rights on a specific page directly from the debugger.

By default, `GDB` does not allow you to do that, so the command will modify a
code section of the binary being debugged, and add a native mprotect syscall
stub. For example, for an x86, the following stub will be inserted:

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

`mprotect` is a `gef` for `set-permission`. For example, to set the `stack` as
READ|WRITE|EXECUTE on this binary,

![mprotect-before](https://i.imgur.com/RRYHxzW.png)

Simply run

```
gef> mprotect 0xfffdd000
```

Et voilà !

![mprotect-after](https://i.imgur.com/9MvyQi8.png)


## `assemble` command

If you have installed [`radare2`](http://radare.org) and `rasm2` binary can be
found in your system $PATH, then `gef` will provide a convenient command to
assemble native instructions directly to opcodes of the architecture you are
currently debugging.

Call it via `assemble` or its alias `asm`:

```
gef> asm main
```

![r2-assemble](https://i.imgur.com/ShuPF6h.png)


## `unicorn` command

If you have installed [`unicorn`](http://unicorn-engine.org) emulation engine
and its Python bindings, `gef` integrates a new command to emulate instructions
of your current debugging context !

This command, `unicorn-emulate` (or its alias `emulate`) will replicate for you
the current memory mapping (including the page permissions), and by default
(i.e. without any additional argument), it will emulate the execution of the
instruction about to be executed (i.e. the one pointed by `$pc`) and display
which register(s) is(are) tainted by it.

Use `-h` for help
```
gef> emu -h
```

For example, the following command will execute only the next 2 instructions:
```
gef> emu -n 2
```

And showing this:
![emu](https://i.imgur.com/DmVH6o1.png)

In this example, we can see that after executing
```
0x80484db	 <main+75>  xor    eax,eax
0x80484dd	 <main+77>  add    esp,0x18
```
The registers `eax` and `esp` are tainted (modified).

A convenient option is `-e /path/to/file.py` that will generate a pure Python
script embedding your current execution context, ready to be re-used outside
`gef`!! This can be useful for dealing with obfuscation or solve crackmes if
powered with a SMT for instance.


## `trace-run` command

The `trace-run` is meant to be provide a visual appreciation directly in IDA
disassembler of the path taken by a specific execution. It should be used with
the IDA script
[`ida_color_gdb_trace.py`](https://github.com/hugsy/stuff/blob/master/ida_scripts/ida_color_gdb_trace.py)

It will trace and store all values taken by `$pc` during the execution flow,
from its current value, until the value provided as argument.

```
gef> trace-run <address_of_last_instruction_to_trace>
```

![trace-run-1](https://i.imgur.com/yaOGste.png)

By using the script `ida_color_gdb_trace.py` on the text file generated, it will
color the path taken:

![trace-run-2](http://i.imgur.com/oAGoSMQ.png)
