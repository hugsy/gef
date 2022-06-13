# Function `$_got()`

Return the current GOT base address plus the given offset.

_Note_: a debugging session must be active

```
$_got([offset])
```

Example:
```
gef➤ p $_got(0x20)
```

