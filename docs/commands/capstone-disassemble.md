## Command capstone-disassemble ##


If you have installed [`capstone`](http://capstone-engine.org) library and its
Python bindings, you can use it to disassemble any location in your debugging
session. This plugin was done to offer an alternative to `GDB` disassemble
function which sometimes gets things mixed up :)

You can use its alias `cs-disassemble` and the location to disassemble (if not
specified, it will use `$pc`).

```
gef➤ cs main
```

![cs-disassemble](https://i.imgur.com/wypt7Fo.png)


