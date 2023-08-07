## Function `$_stack()`

Return the current stack base address plus the given offset.

_Note_: a debugging session must be active

```text
$_stack([offset])
```

Example:

```text
gef➤ p $_stack(0x20)
```
