# Function `$_bss()`

Return the current BSS base address plus the given offset.

_Note_: a debugging session must be active

```
$_bss([offset])
```

Example:
```
gef➤ p $_bss(0x20)
```

