# Function `$_base()`

Return the matching file's base address plus an optional offset. Defaults to current file. Note that quotes need to be escaped.

_Note_: a debugging session must be active

```
$_base([filepath])
```

Example:
```
gef➤ p $_base(\"/usr/lib/ld-2.33.so\")
```

