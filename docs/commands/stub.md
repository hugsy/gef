## Command stub ##

The `stub` command allows you stub out functions, optionally specifying the
return value.

```
gef➤  stub [-h] [-r RETVAL] [LOCATION]
```

`LOCATION` indicates the address of the function to bypass. If not
specified, gef will consider the instruction at the program counter to be the
start of the function.

If `-r RETVAL` is provided, gef will set the return value to the provided
value. Otherwise it will set the return value to 0.
