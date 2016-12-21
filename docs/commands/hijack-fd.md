## Command hijack-fd ##

`gef` can be used to modify file descriptors of the debugged process. The new
file descriptor can point to a file, a pipe, a socket, a device etc.

To use it, simply run
```
gef➤ hijack-fd FDNUM NEWFILE
```

For instance,
```
gef➤ hijack-fd 1 /dev/null
```
Will modify the current process file descriptors to redirect STDOUT to
`/dev/null`.

Check this asciicast for visual example:
[![asciicast](https://asciinema.org/a/2o9bhveyikb1uvplwakjftxlq.png)](https://asciinema.org/a/2o9bhveyikb1uvplwakjftxlq)
