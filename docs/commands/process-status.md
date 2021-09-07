## Command process-status ##

> This command replaces the old commands `pid` and `fd`.

`process-status` provides an exhaustive description of the current running
process, by extending the information provided by GDB `info proc` command, with
all the information from the `procfs` structure.

```
gef➤ ps --smart-scan zsh
22879
gef➤ attach 22879
[...]
gef➤ status
[+] Process Information
        PID  →  22879
        Executable  →  /bin/zsh
        Command line  →  '-zsh'
[+] Parent Process Information
        Parent PID  →  4475
        Command line  →  'tmux new -s cool vibe
[+] Children Process Information
        PID  →  26190 (Name: '/bin/sleep', CmdLine: 'sleep 100000')
[+] File Descriptors:
        /proc/22879/fd/0  →  /dev/pts/4
        /proc/22879/fd/1  →  /dev/pts/4
        /proc/22879/fd/2  →  /dev/pts/4
        /proc/22879/fd/10  →  /dev/pts/4
[+] File Descriptors:
        No TCP connections
```
