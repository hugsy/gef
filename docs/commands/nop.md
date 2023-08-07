## Command `nop`

The `nop` command allows you to easily patch instructions with nops.

```text
nop [LOCATION] [--i ITEMS] [--f] [--n] [--b]
```

`LOCATION` address/symbol to patch (by default this command replaces whole instructions)

`--i ITEMS` number of items to insert (default 1)

`--f` Force patch even when the selected settings could overwrite partial instructions

`--n` Instead of replacing whole instructions, insert ITEMS nop instructions, no matter how many
instructions it overwrites

`--b` Instead of replacing whole instructions, fill ITEMS bytes with nops

nop the current instruction ($pc):

```text
gef➤ nop
```

nop an instruction at $pc+3 address:

```text
gef➤ nop $pc+3
```

nop two instructions at address $pc+3:

```text
gef➤ nop --i 2 $pc+3
```

Replace 1 byte with nop at current instruction ($pc):

```text
gef➤ nop --b
```

Replace 1 byte with nop at address $pc+3:

```text
gef➤ nop --b $pc+3
```

Replace 2 bytes with nop(s) (breaking the last instruction) at address $pc+3:

```text
gef➤ nop --f --b --i 2 $pc+3
```

Patch 2 nops at address $pc+3:

```text
gef➤ nop --n --i 2 $pc+3
```
