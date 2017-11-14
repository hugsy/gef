## Command pie ##

The `pie` command provides a useful way to set breakpoint to a PIE enabled binary.
`pie` command then provides what we call "PIE breakpoint". A PIE breakpoint is just
a virtual breakpoint which will be set to real breakpoint when the process is attaching.
A PIE breakpoint's address is the offset from binary base address.

Note that you need to use ENTIRE PIE COMMAND SERIES to support PIE breakpoint, especially the
"attaching" commands provided by `pie` command, like `pie attach`, `pie run`, etc.

Usage is just:
```
gef➤ pie <sub_commands>
```


### `pie breakpoint` command ###

This command sets a new PIE breakpoint. It can be used like normal `breakpoint` command
in gdb. The location is just the offset from the base address. Breakpoint will not be
set immediately after this command. Instead, it will be set when you use `pie attach`,
`pie run`, `pie remote` to actually attach to a process, so it can resolve the right base
address.

Usage:
```
gef➤ pie breakpoint <LOCATION>
```

### `pie info` command ###

Since PIE breakpoint is not real breakpoint, this command provide a way to observe the
state of all PIE breakpoints.

This is just like `info breakpoint` in gdb.
```
gef➤  pie info
VNum	Num	Addr
1	N/A	0xdeadbeef
```

The VNum is the virtual number, which is the number of the PIE breakpoint. The Num is the
number of the according real breakpoint number in gdb. Address is the PIE breakpoint's
address.

You can ignore VNum argument to get info of all PIE breakpoints.

Usage:
```
gef➤  pie info [VNum]

```


### `pie delete` command ###

This command deletes a PIE breakpoint given a VNum of that PIE breakpoint.

Usage:
```
gef➤  pie delete <VNum>
```


### `pie attach` command ###

The same as gdb's `attach` command. Always use this command instead of raw `attach` 
if you have PIE breakpoint. This will set real breakpoint when attaching.

The usage is just the same as `attach`.

### `pie remote` command ###
The same as gdb's `remote` command. Always use this command instead of raw `remote`
if you have PIE breakpoint. This will set real breakpoint when attaching.

The usage is just the same as `remote`.

### `pie run` command ###
The same as gdb's `run` command. Always use the command instead of raw `run` if you 
have PIE breakpoint. This will set real breakpoint when attaching.

The usage is just the same as `run`.
