## Command shellcode ##

`shellcode` is a command line client for @JonathanSalwan shellcodes database. It
can be used to search and download directly via `GEF` the shellcode you're
looking for. Two primitive subcommands are available, `search` and `get`

```
gef➤ shellcode search arm
[+] Showing matching shellcodes
901     Linux/ARM       Add map in /etc/hosts file - 79 bytes
853     Linux/ARM       chmod("/etc/passwd", 0777) - 39 bytes
854     Linux/ARM       creat("/root/pwned", 0777) - 39 bytes
855     Linux/ARM       execve("/bin/sh", [], [0 vars]) - 35 bytes
729     Linux/ARM       Bind Connect UDP Port 68
730     Linux/ARM       Bindshell port 0x1337
[...]
gef➤ shellcode get 698
[+] Downloading shellcode id=698
[+] Shellcode written as '/tmp/sc-EfcWtM.txt'
gef➤ system cat /tmp/sc-EfcWtM.txt
/*
Title:     Linux/ARM - execve("/bin/sh", [0], [0 vars]) - 27 bytes
Date:      2010-09-05
Tested on: ARM926EJ-S rev 5 (v5l)
Author:    Jonathan Salwan - twitter: @jonathansalwan

shell-storm.org

Shellcode ARM without 0x20, 0x0a and 0x00
[...]
```

