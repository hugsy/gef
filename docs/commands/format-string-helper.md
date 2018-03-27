## Command format-string-helper ##

The `format-string-helper` command will create a `GEF` specific type of
breakpoints dedicated to detecting potentially insecure format string when
using the GlibC library.

It will use this new breakpoint against several targets, including:

* `printf()`
* `sprintf()`
* `fprintf()`
* `snprintf()`
* `vsnprintf()`

Just call the command to enable this functionality.

`fmtstr-helper` is a shorter alias.

```
gef➤ fmtstr-helper
```

Then start the binary execution.
```
gef➤ r
```

If a potentially insecure entry is found, the breakpoint will trigger, stop the
process execution, display the reason for trigger and the associated context.

![fmtstr-helper-example](https://i.imgur.com/INU3KGn.png)

