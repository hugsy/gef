## Function `$_bss()`

Return the current BSS base address plus the given offset.

_Note_: a debugging session must be active

```text
$_bss([offset])
```

Example:

```text
gef➤ p $_bss(0x20)
```
