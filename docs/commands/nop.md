## Command nop ##

The `nop` command allows you to easily skip instructions.

```
gef ➤  help nop
Patch the instruction(s) pointed by parameters with NOP. Note: this command is architecture
aware.
Syntax: nop [LOCATION] [--nb NUM_BYTES]
  LOCATION      address/symbol to patch
    --nb NUM_BYTES      Instead of writing one instruction, patch the specified number of bytes
```

`LOCATION` indicates the address of the instruction to bypass. If not
specified, it will use the current value of the program counter.

If `--nb <bytes>` is entered, gef will explicitly patch the specified number of
bytes.  Otherwise it will patch the _whole_ instruction at the target location.
