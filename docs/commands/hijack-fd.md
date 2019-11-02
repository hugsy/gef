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


This command also supports connecting to an ip:port if it is provided as an argument. For example
```
gef➤ hijack-fd 0 localhost:8888
```
Will redirect STDIN to localhost:8888


Check out the tutorial on GEF's YouTube channel:

[![yt-tuto-hijack-fd](https://img.youtube.com/vi/Ss_QFeYkEvk/0.jpg)](https://www.youtube.com/watch?v=Ss_QFeYkEvk)

