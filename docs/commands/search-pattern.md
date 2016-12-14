## Command search-pattern ##

The `edit-flags` command (alias: `flags`) provides a quick and comprehensible
way to view and edit the flag register for the architectures that support it.
Without argument, the command will simply return a human-friendly display of the
register flags.

One or many arguments can be provided, following the syntax below:
```
gef> flags [(+|-|~)FLAGNAME ...]
```
Where `FLAGNAME` is the name of the flag (case insensitive), and `+|-|~` indicates
the action on wether to set, unset, or toggle the flag.

For instance, on x86 architecture, if we don't want to take a conditional jump
(`jz` condition), but we want to have the Carry flag set, simply go with:

```
gef> flags -ZERO +CARRY
```
![flags](https://i.imgur.com/ro7iC5m.png)


## `search-pattern` command ##

`gef` allows you to search for a specific pattern at runtime in all the segments
of your process memory layout. The command `search-pattern`, alias `grep`, aims
to be straight-forward to use:
```
gef> search-pattern MyPattern
```

![grep](https://camo.githubusercontent.com/79c14e46fd1c1616cacab37d88b49aae7e00560e/68747470733a2f2f692e696d6775722e636f6d2f656e78456451642e706e67)



