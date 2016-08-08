# Features #

This page will explain in details some non-trivial commands available in `GEF`
with examples and screenshots to make it easier to reproduce.

## `context` command ##

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


## `entry-break` command ##

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


## `patch` command ##

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


## `xinfo`/`vmmap`/`xfiles` commands ##

`xinfo`, `vmmap` and `xfiles` display a comprehensive and human-friendly memory
mapping of either the process or a specific location.

![vmmap-example](https://i.imgur.com/iau8SwS.png)

Interestingly, it helps finding secret gems: as an aware reader might have seen,
memory mapping differs from one architecture to another (this is one of the main
reasons I started `GEF` in a first place). For example, you can learn that
ELF running on SPARC architectures always have their `.data` and `heap` sections set as
Read/Write/Execute.

![xinfo-example](https://pbs.twimg.com/media/CCSW9JkW4AAx8gD.png:large)


## `heap` command ##

`heap` command provides information on the heap chunk specified as argument. For
the moment, it only supports GlibC heap format (see
[this link](http://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)
for  `malloc` structure information). Syntax to the
subcommands is pretty straight forward :

```
gef> heap <sub_commands>
```

### `heap chunk` command ###

This command gives visual information of a Glibc malloc-ed chunked. Simply
provide the address to the user memory pointer of the chunk to show the
information related to the current chunk:

```
gef> heap chunk <LOCATION>
```

![heap-chunks](https://i.imgur.com/SAWNptW.png)


### `heap arenas` command ###

Multi-threaded programs have different arenas, and the only knowledge of the
`main_arena` is not enough.
`gef` therefore provides the `arena` sub-commands to help you list all the
arenas allocated in your program **at the moment you call the command**.

![heap-arena](https://i.imgur.com/ajbLiCF.png)


### `heap bins` command ###

Glibc bins are the structures used for keeping tracks of free-ed chunks. The
reason for that is that allocation (using `sbrk`) is costly. So Glibc uses those
bins to remember formely allocated chunks. Because bins are structured in single
or doubly linked list, I found that quite painful to always interrogate `gdb` to
get a pointer address, dereference it, get the value chunk, etc... So I
decided to implement in `gef` the `heap bins` sub-command, which allows to get info on:

   - `fastbins`
   - `bins`
      - `unsorted`
      - `small bins`
      - `large bins`


#### `heap bins fast` command ####

When exploiting heap corruption vulnerabilities, it is sometimes convenient to
know the state of the `fastbinsY` array.
The `fast` sub-command helps by displaying the list of fast chunks in this
array. Without any other argument, it will display the info of the `main_arena`
arena. It accepts an optional argument, the address of another arena (which you
can easily find using `heap arenas`).

```
gef➤ heap bins fast
[+] FastbinsY of arena 0x7ffff7dd5b20
Fastbin[0] 0x00
Fastbin[1]  →  FreeChunk(0x600310)  →  FreeChunk(0x600350)
Fastbin[2] 0x00
Fastbin[3] 0x00
Fastbin[4] 0x00
Fastbin[5] 0x00
Fastbin[6] 0x00
Fastbin[7] 0x00
Fastbin[8] 0x00
Fastbin[9] 0x00
```

#### Other `heap bins X` command ####

All the other subcommands for the `heap bins` works the same way than `fast`. If
no argument is provided, `gef` will fall back to `main_arena`. Otherwise, it
will use the address pointed as the base of the `malloc_state` structure and
print out information accordingly.



## `shellcode` command ##

`shellcode` is a command line client for @JonathanSalwan shellcodes database. It
can be used to search and download directly via `GEF` the shellcode you're
looking for. Two primitive subcommands are available, `search` and `get`

```
gef➤ shellcode search arm
[+] Showing matching shellcodes
901     Linux/ARM       Add map in /etc/hosts file - 79 bytes
853     Linux/ARM       chmod("/etc/passwd", 0777) - 39 bytes
854     Linux/ARM       creat("/root/pwned", 0777) - 39 bytes
855     Linux/ARM       execve("/bin/sh", [], [0 vars]) - 35 bytes
729     Linux/ARM       Bind Connect UDP Port 68
730     Linux/ARM       Bindshell port 0x1337
[...]
gef➤ shellcode get 698
[+] Downloading shellcode id=698
[+] Shellcode written as '/tmp/sc-EfcWtM.txt'
gef➤ system cat /tmp/sc-EfcWtM.txt
/*
Title:     Linux/ARM - execve("/bin/sh", [0], [0 vars]) - 27 bytes
Date:      2010-09-05
Tested on: ARM926EJ-S rev 5 (v5l)
Author:    Jonathan Salwan - twitter: @jonathansalwan

shell-storm.org

Shellcode ARM without 0x20, 0x0a and 0x00
[...]
```

## `format-string-helper` command ##

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
gef➤ fmtstr-helper
```

Then start the binary execution.
```
gef➤ g
```

If a potentially insecure entry is found, the breakpoint will trigger, stop the
process execution, display the reason for trigger and the associated context.

![fmtstr-helper-example](https://i.imgur.com/INU3KGn.png)


## `gef-remote` debugging ##

It is possible to use `gef` in a remote debugging environment.


### With a local copy ###

If you want to remotely debug a binary that you already have, you simply need to
specify to `gdb` where to find the debug information.

For example, if we want to debug `uname`, we do on the server:
```
$ gdbserver 0.0.0.0:1234 /bin/uname
Process /bin/uname created; pid = 32280
Listening on port 1234
```
![](https://i.imgur.com/Zc4vnBd.png)

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


### Without a local copy ###

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

![gef-remote-autodownload](https://i.imgur.com/8JHpOTV.png)

You can then reuse the downloaded file for your future debugging sessions, use it under IDA
and such. This makes the entire remote debugging process (particularly for Android applications)
a child game.


## `capstone-disassemble` command ##

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


## `set-permission` command ##

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

`mprotect` is an alias for `set-permission`. As an example, to set the `stack` as
READ|WRITE|EXECUTE on this binary,

![mprotect-before](https://i.imgur.com/RRYHxzW.png)

Simply run

```
gef> mprotect 0xfffdd000
```

Et voilà ! `gef` will use the memory runtime information to correctly adjust the protection
of the entire section.

![mprotect-after](https://i.imgur.com/9MvyQi8.png)

Or for a full demo video on a PowerPC VM:
[![asciicast](https://asciinema.org/a/54noulja01k3cgctawjeio8xl.png)](https://asciinema.org/a/54noulja01k3cgctawjeio8xl)


## `assemble` command ##

If you have installed [`keystone`](http://www.keystone-engine.org/), then `gef` will provide
a convenient command to assemble native instructions directly to opcodes of the
architecture you are currently debugging.

Call it via `assemble` or its alias `asm`:

```
gef> asm main
```

![gef-assemble](https://i.imgur.com/ShuPF6h.png)


## `unicorn` command ##

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


## `trace-run` command ##

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


## `edit-flags` command ##

The `edit-flags` command (alias: `flags`) provides a quick and comprehensible
way to view and edit the flag register for the architectures that support it.
Without argument, the command will simply return a human-friendly display of the
register flags.

One or many arguments can be provided, following the syntax below:
```
gef> flags [+|-]FLAGNAME ([+|-]FLAGNAME...)
```
Where `FLAGNAME` is the name of the flag (case insensitive), and `+|-` indicates
the action on wether to set the flag or not.

For instance, on x86 architecture, if we don't want to take a conditional jump
(`jz` condition), but we want to have the Carry flag set, simply go with:

```
gef> flags -ZERO +CARRY
```
![flags](https://i.imgur.com/ro7iC5m.png)


## `search-pattern` command ##

`gef` allows you to search for a specific pattern at runtime in all the segments
of your process memory layout. The command `search-pattern`, alias `grep`, aims
to be straight-forward to use:
```
gef> search-pattern MyPattern
```

![grep](https://camo.githubusercontent.com/79c14e46fd1c1616cacab37d88b49aae7e00560e/68747470733a2f2f692e696d6775722e636f6d2f656e78456451642e706e67)



## `ida-interact` command ##

`gef` provides a simple XML-RPC client designed to communicate with a server
running inside a specific IDA Python plugin, called `ida_gef_xmlrpc.py` (which
can be downloaded freely
[here](https://github.com/hugsy/stuff/blob/master/ida_scripts/ida_gef_xmlrpc.py)).

Simply download this script, and run it inside IDA. When the server is running,
you will see a text in the Output Window such as:

```
[+] Creating new thread for XMLRPC server: Thread-1
[+] Starting XMLRPC server: 0.0.0.0:1337
[+] Registered 6 functions.
```

This indicates that the XML-RPC server is ready and listening.

`gef` can interact with it via the command `ida-interact`. This command receives
as first argument the name of the function to execute, all the other arguments
are the arguments of the remote function.

To enumerate the functions available, simply run
```
gef➤  ida-interact -h
```
![gef-ida-help](https://i.imgur.com/JFNBfjY.png)

Now, to execute an RPC, invoke the command `ida-interact` on the desired method,
with its arguments (if required).

For example:
```
gef➤  ida ida.set_color 0x40061E
```
will edit the remote IDB and set the background color of the location 0x40061E
with the color 0x005500 (default value).

Another convenient example is to add comment inside IDA directly from `gef`:
```
gef➤  ida ida.add_comment 0x40060C "<<<--- stack overflow"
[+] Success
```

Result:

![gef-ida-example](https://i.imgur.com/jZ2eWG4.png)

Please use the `--help` argument to see all the methods available and their
syntax.

## `hijack-fd` command ##

`gef` can be used to modify file descriptors of the debugged process. The new
file descriptor can point to a file, a pipe, a socket, a device etc.

To use it, simply run
```
gef➤ hijack-fd FDNUM NEWFILE
```

For instance,
```
gef➤ hijack-fd 1 /dev/null
```
Will modify the current process file descriptors to redirect STDOUT to
`/dev/null`.

Check this asciicast for visual example:
[![asciicast](https://asciinema.org/a/2o9bhveyikb1uvplwakjftxlq.png)](https://asciinema.org/a/2o9bhveyikb1uvplwakjftxlq)


## `retdec` command ##

`gef` uses the RetDec decompilation Web API (https://retdec.com/decompilation)
to decompile parts of or entire binary. The command, `retdec`, also has a
default alias, `decompile` to make it easier to remember.

To use the command, you need to provide `gef` a valid RetDec API key, available
by registering [here](https://retdec.com/registration/) (free accounts).

Then enter the key through the `gef config` command:
```
gef➤ gef config retdec.key 1234-1234-1234-1234
```

You can have `gef` save this key by saving the current configuration settings.
```
gef➤ gef save
```

`retdec` can be used in 3 modes:

   * By providing the option `-a`, `gef` will submit the entire binary being
     debugged to RetDec. For example,
```
gef➤ decompile -a
```
![gef-retdec-full](https://i.imgur.com/PzBXf3U.png)

   * By providing the option `-r START:END`, `gef` will submit only the raw
     bytes contained within the range specified as argument.

   * By providing the option `-s SYMBOL`, `gef` will attempt to reach a specific
     function symbol, dump the function in a temporary file, and submit it to
     RetDec. For example,
```
gef➤ decompile -s main
```
![gef-retdec-symbol-main](https://i.imgur.com/76Yl9iD.png)


## `pcustom` command ##

`gef` provides a way to create and apply to the currently debugged environment,
any new structure (in the C-struct way). On top of simply displaying known
and user-defined structures, it also allows to apply those structures to the
current context. It intends to mimic the very useful
[WinDBG `dt`](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542772(v=vs.85).aspx)
command.

This is achieved via the command `pcustom` (for `print custom`), or you can use
its alias, `dt` (in reference to the WinDBG command).

### Configuration

New structures can be stored in the location given by the configuration setting:
```
gef➤ gef config pcustom.struct_path
```
By default, this location is in `/tmp/gef/structs`. The structure can be created
as a simple `ctypes` structure, in a file called `<struct_name>.py`.

You can naturally set this path to a new location
```
gef➤ gef config pcustom.struct_path /my/new/location
```
And save this change so you can re-use it directly next time you use `gdb`
```
gef➤ gef save
[+] Configuration saved to '~/.gef.rc'
```

### Using user-defined structures

You can list existing custom structures via
```
gef➤  dt -l
[+] Listing custom structures:
 →  struct5
 →  struct6
```

To create or edit a structure, use `dt <struct_name> -e` to spawn your EDITOR
with the targeted structure. If the file does not exist, `gef` will nicely
create the tree and file, and fill it with a `ctypes` template that you can use
straight away!
```
gef➤  dt foo -e
[+] Creating '/tmp/gef/structs/foo.py' from template
```

The code can be defined just as any Python (using `ctypes`) code.

```
from ctypes import *

'''
typedef struct {
  int age;
  char name[256];
  int id;
} person;
'''

class Template(Structure):
    _fields_ = [
        ("age",  c_int),
        ("name", c_char * 256),
        ("id", c_int),
    ]

```

`pcustom` requires at least one argument, which is the name of the
structure. With only one argument, `pcustom` will dump all the fields of this
structure.

```
gef➤  dt person
+0000 age c_int (0x4)
+0004 name c_char_Array_256 (0x100)
+0104 id c_int (0x4)
```

By providing an address or a GDB symbol, `gef` will apply this user-defined
structure to the specified address:

![gef-pcustom-with-address](https://i.imgur.com/vWGnu5g.png)

This means that we can now create very easily new user-defined structures

Watch the demonstration video on Asciinema:

[![asciicast](https://asciinema.org/a/bhsguibtf4iqyyuomp3vy8iv2.png)](https://asciinema.org/a/bhsguibtf4iqyyuomp3vy8iv2)

Additionally, if you have successfully configured your IDA settings (see command
`ida-interact`), you can also directly import the structure(s) that was(were)
reverse-engineered in IDA directly in your GDB session:

![ida-structure-examples](https://i.imgur.com/Tnsf6nt.png)

And then use the command `ida ImportStructs` to import all the structures, or
`ida ImportStruct <StructName>` to only import a specific one:

```
gef➤  ida ImportStructs
[+] Success
```

Which will become:

![ida-structure-imported](https://i.imgur.com/KVhyopO.png)
