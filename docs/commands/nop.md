## Command nop ##

The `nop` command allows to easily bypass a call or syscall, by replacing the
instruction pointed by the `LOCATION` argument with (per-architecture) NOPs. The
syntax is as following:

```
gef➤ nop [-r VALUE] [-p] [-h] [LOCATION]
```

`LOCATION` indicates the instruction to bypass. If none specified, it will use
the current value of the program counter. `patch` will overwrite the whole
instruction with NOPs (or equivalent, depending on the architecture).

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

   * Before `nop`
![before-nop](https://i.imgur.com/Gr5g45S.png)

   * Apply `nop` and force return register to `0`
```
gef➤ nop -r 0 0x400596
```
![apply-nop](https://i.imgur.com/hYE2sv2.png)

   * After `nop`
![after-nop](https://i.imgur.com/iEZVJWb.png)

