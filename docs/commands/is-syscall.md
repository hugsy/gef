## Command is-syscall ##

`gef` can be used to determine whether the instruction to be executed next is a system call.

To use it, simply run
```
gef➤ is-syscall
```

If it is a system call,
```
gef➤ is-syscall
[+] Current instruction is a syscall
```

Check this asciicast for visual example:
[![asciicast](https://asciinema.org/a/FU11vmLtlYVBgRhKLaqSPd4Od.png)](https://asciinema.org/a/FU11vmLtlYVBgRhKLaqSPd4Od)
