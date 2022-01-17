## Command checksec ##

The `checksec` command is inspired from
[`checksec.sh`](https://www.trapkit.de/tools/checksec.html). It provides a
convenient way to determine which security protections are enabled in a binary.

You can use the command on the currently debugged process:
```
gef➤  checksec
[+] checksec for '/vagrant/test-bin'
Canary:                                           No
NX Support:                                       Yes
PIE Support:                                      No
No RPATH:                                         Yes
No RUNPATH:                                       Yes
Partial RelRO:                                    Yes
Full RelRO:                                       No
```

Or specify directly the binary to check, for example:

```bash
$ gdb -ex "checksec ./tests/test-x86"
```
