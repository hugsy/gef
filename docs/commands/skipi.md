## Command `skipi`

The `skipi` command allows you to easily skip instructions execution.

```text
skipi [LOCATION] [--n NUM_INSTRUCTIONS]
```

`LOCATION` address/symbol from where to skip (default is `$pc`)

`--n NUM_INSTRUCTIONS` Skip the specified number of instructions instead of the default 1.

```bash
gef➤  skipi
gef➤  skipi --n 3
gef➤  skipi 0x69696969
gef➤  skipi 0x69696969 --n 6
```
