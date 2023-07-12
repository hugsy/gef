## Command `nopi`

The `nopi` command allows you to easily skip instructions.

```
gef ➤  help nopi
Patch the number of full instructions pointed by parameters with NOP. Note: this command is architecture
aware.
Syntax: nopi [LOCATION] [--ni NUM_INSTRUCTIONS]
  LOCATION      address/symbol to patch
    --ni NUM_INSTRUCTIONS      Instead of writing one instruction, patch the specified number of instructions
```

`LOCATION` indicates the address of the instruction to bypass. If not
specified, it will use the current value of the program counter.

If `--ni <number of instructions>` is entered, gef will explicitly patch the specified number of
instructions.  Otherwise it will patch one instruction at the target location.
