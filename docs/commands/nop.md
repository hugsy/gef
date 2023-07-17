## Command `nop`

The `nop` command allows you to easily patch instructions with nops.

```
nop [LOCATION] [--n NUM_ITEMS] [--b]
```

`LOCATION` address/symbol to patch

`--n NUM_ITEMS` Instead of writing one instruction/nop, patch the specified number of
instructions/nops (full instruction size by default)

`--b` Instead of writing full instruction size, patch the specified number of nops

```bash
gef➤ 	nop
gef➤ 	nop $pc+3
gef➤ 	nop --n 2 $pc+3
gef➤ 	nop --b
gef➤ 	nop --b $pc+3
gef➤ 	nop --b --n 2 $pc+3
```
