## Command edit-flags ##

The `edit-flags` command (alias: `flags`) provides a quick and comprehensible
way to view and edit the flag register for the architectures that support it.
Without argument, the command will simply return a human-friendly display of the
register flags.

One or many arguments can be provided, following the syntax below:
```
gef➤ flags [(+|-|~)FLAGNAME ...]
```
Where `FLAGNAME` is the name of the flag (case insensitive), and `+|-|~` indicates
the action on whether to set, unset, or toggle the flag.

For instance, on x86 architecture, if we don't want to take a conditional jump
(e.g. a `jz` instruction), but we want to have the Carry flag set, simply go with:

```
gef➤ flags -ZERO +CARRY
```
![flags](https://i.imgur.com/ro7iC5m.png)
