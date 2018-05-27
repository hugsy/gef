## Command nop ##

The `nop` command allows you to easily skip instructions.

```
gef➤ nop [-b NUM_BYTES] [-h] [LOCATION]
```

`LOCATION` indicates the address of the instruction to bypass. If not
specified, it will use the current value of the program counter.

If `-b <bytes>` is entered, gef will explicitly patch the specified number of
bytes.  Otherwise it will patch the _whole_ instruction at the target location.
