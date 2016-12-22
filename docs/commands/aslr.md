## Command aslr

Check, enable or disable easily ASLR on the debugged binary.

Check the status:
```
gef➤  aslr
ASLR is currently disabled
```

Activate ASLR:
```
gef➤  aslr on
[+] Enabling ASLR
gef➤  aslr
ASLR is currently enabled
```

De-activate ASLR:
```
gef➤  aslr off
[+] Disabling ASLR
```

**Note**: This command cannot have effect on process already loaded, to which
GDB was attached later on. The only way to disable this randomization is by
setting to 0 the kernel variable `/proc/sys/kernel/randomize_va_space`.
