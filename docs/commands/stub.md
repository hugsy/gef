## Command stub ##

The `stub` command allows you stub out functions, optionally specifying the
return value.

```
gef➤  stub [-h] [--retval RETVAL] [address]
```

`address` indicates the address of the function to bypass. If not
specified, `GEF` will consider the instruction at the program counter to be the
start of the function.

If `--retval RETVAL` is provided, `GEF` will set the return value to the
provided value. Otherwise, it will set the return value to 0.

For example, it is trivial to bypass `fork()` calls. Since the return value is
set to 0, it will in fact drop us into the "child" process. It must be noted
that this is a different behaviour from the classic `set follow-fork-mode
child` since here we do not spawn a new process, we only trick the parent
process into thinking it has become the child.

### Example ###

Patching `fork()` calls:

* Without stub:

![fork execution](https://i.imgur.com/TjnTDot.png)

* With stub:

![stubbed fork](https://i.imgur.com/CllTnRH.png)
