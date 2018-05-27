## Command unicorn-emulate ##

If you have installed [`unicorn`](http://unicorn-engine.org) emulation engine
and its Python bindings, `gef` integrates a new command to emulate instructions
of your current debugging context !

This command, `unicorn-emulate` (or its alias `emu`) will replicate the current
memory mapping (including the page permissions) for you, and by default (i.e.
without any additional argument), it will emulate the execution of the
instruction about to be executed (i.e. the one pointed by `$pc`) and display
which register(s) is(are) tainted by it.

Use `-h` for help
```
gef➤ emu -h
```

For example, the following command will execute only the next 2 instructions:
```
gef➤ emu -n 2
```

And show this:
![emu](https://i.imgur.com/DmVH6o1.png)

In this example, we can see that after executing
```
0x80484db	 <main+75>  xor    eax,eax
0x80484dd	 <main+77>  add    esp,0x18
```
The registers `eax` and `esp` are tainted (modified).

A convenient option is `-o /path/to/file.py` that will generate a pure Python
script embedding your current execution context, ready to be re-used outside
`gef`!! This can be useful for dealing with obfuscation or solve crackmes if
powered with a SMT for instance.


