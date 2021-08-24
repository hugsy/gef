## Command pie ##

The `pie` command is handy when working with position-independent executables.
At runtime, it can automatically resolve addresses for breakpoints that are not
static.

Note that you need to use the **entire `pie` command series** to support PIE
breakpoints, especially the "`pie` run commands", like `pie attach`, `pie run`,
etc.

### `pie breakpoint` command ###

This command sets a new PIE breakpoint. It can be used like the normal
`breakpoint` command in gdb. The argument for the command is the offset from
the base address or a symbol. The breakpoints will not be set immediately after
this command. Instead, it will be set when you use `pie attach`, `pie run` or
`pie remote` to actually attach to a process, so it can resolve the right base
address.

Usage:

```
gef➤ pie breakpoint OFFSET
```

### `pie info` command ###

Since a PIE breakpoint is not a real breakpoint, this command provides a way to
observe the state of all PIE breakpoints.

This works just like `info breakpoint` in gdb.

```
gef➤  pie info
VNum    Num     Addr
1       N/A     0xdeadbeef
```

VNum stands for virtual number and is used to enumerate the PIE breakpoints.
Num is the number of the associated real breakpoints at runtime in GDB.

You can omit the VNum argument to get info on all PIE breakpoints.

Usage:

```
gef➤  pie info [VNum]

```

### `pie delete` command ###

This command deletes a PIE breakpoint given its VNum.

Usage:

```
gef➤  pie delete [VNum]
```

### `pie attach` command ###

This command behaves like GDB's `attach` command. Always use this command
instead of `attach` if you have PIE breakpoints. This will convert the PIE
breakpoints to real breakpoints at runtime.

The usage is just the same as `attach`.

### `pie remote` command ###

This command behaves like GDB's `remote` command. Always use this command
instead of `remote` if you have PIE breakpoints. Behind the scenes this will
connect to the remote target using `gef remote` and then convert the PIE
breakpoints to real breakpoints at runtime.

The usage is just the same as `remote`.

### `pie run` command ###

This command behaves like GDB's `run` command. Always use this command instead
of `run` if you have PIE breakpoints. This will convert the PIE breakpoints to
real breakpoints at runtime.

The usage is just the same as `run`.
