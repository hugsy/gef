# Function `$_stack()`

Return the current stack base address plus the given offset.

_Note_: a debugging session must be active

```
$_stack([offset])
```

Example:
```
gef➤ p $_stack(0x20)
```


