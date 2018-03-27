## Command entry-break ##

The `entry-break` (alias `start`) command's goal is to find and break at the
most obvious entry point available in the binary. Since the binary will start
running, some of the `PLT` entries will also be resolved, making further
debugging easier.

It will perform the following actions:

1. Look up a `main` symbol. If found, set a temporary breakpoint and go.
2. Otherwise, it will look up for `__libc_start_main`. If found, set a
temporary breakpoint and go.
3. Finally, if the previous two symbols are not found, it will get the entry
point from the ELF header, set a breakpoint and run. This case should never
fail if the ELF binary has a valid structure.

![entry-break-example](https://i.imgur.com/zXSERMh.png)
