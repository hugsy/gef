# Function `$_heap()`

Return the current heap base address plus the given offset.

_Note_: a debugging session must be active

```
$_heap([offset])
```

Example:
```
gef➤ p $_heap(0x20)
```

