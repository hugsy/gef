## Command unicorn-emulate ##

If you have installed [`unicorn`](http://unicorn-engine.org) emulation engine
and its Python bindings, GEF integrates a new command to emulate instructions
of your current debugging context !

This `unicorn-emulate` command (or its alias `emu`) will replicate the current
memory mapping (including the page permissions) for you, and by default (i.e.
without any additional argument), it will emulate the execution of the
instruction about to be executed (i.e. the one pointed by `$pc`). Furthermore
the command will print out the state of the registers before and after the
emulation.

Use `-h` for help:

```
gef➤ emu -h
```

For example, the following command will emulate only the next 2 instructions:

```
gef➤ emu 2
```

And show this:

![emu](https://i.imgur.com/n4Oy5D0.png)

In this example, we can see that after executing

```
0x555555555171 <main+8>         sub    rsp, 0x10
0x555555555175 <main+12>        mov    edi, 0x100
```

The registers `rsp` and `rdi` are tainted (modified).

A convenient option is `--output-file /path/to/file.py` that will generate a
pure Python script embedding your current execution context, ready to be re-used
outside GEF!! This can be useful for dealing with obfuscation or solve crackmes
if powered with a SMT for instance.


