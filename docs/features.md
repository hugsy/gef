# Features

This page will explain in details some non-trivial commands available in `GEF`
with examples and screenshots to make it easier to reproduce.


## entry-break command

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

![entry-break-example](http://i.imgur.com/zXSERMh.png)


## patch command

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
![before-patch](http://i.imgur.com/Gr5g45S.png)

   * Apply `patch` and force return register to `0`
```
gef> patch -r 0 0x400596
```
![apply-patch](http://i.imgur.com/hYE2sv2.png)

   * After `patch`
![after-patch](http://i.imgur.com/iEZVJWb.png)


## heap command

`heap` command provides information on the heap chunk specified as argument. For
the moment, it only supports GlibC heap format (see
[this link](http://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)
for  `malloc` structure information). Syntax is pretty straight forward

```
gef> heap [LOCATION]
```

will display information like this

![heap-example](https://i.imgur.com/xPcnzWp.png)


## fmtstr-helper command

`fmtstr-helper` command will create a `GEF` specific type of breakpoints
dedicated to detecting potentially insecure format string when using the GlibC
library.

It will use this new breakpoint against several targets, including:

   * `printf()`
   * `sprintf()`
   * `fprintf()`
   * `snprintf()`
   * `vsnprintf()`

Just call the command to enable this functionality.
```
gef> fmtstr-helper
```

Then start the binary execution.
```
gef> g
```

If a potentially insecure entry is found, the breakpoint will trigger, stop the
process execution, display the reason for trigger and the associated context.

![fmtstr-helper-example](http://i.imgur.com/INU3KGn.png)
