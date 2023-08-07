## Command `aslr`

Easily check, enable or disable ASLR on the debugged binary.

Check the status:

```text
gef➤  aslr
ASLR is currently disabled
```

Activate ASLR:

```text
gef➤  aslr on
[+] Enabling ASLR
gef➤  aslr
ASLR is currently enabled
```

De-activate ASLR:

```text
gef➤  aslr off
[+] Disabling ASLR
```

**Note**: This command cannot affect a process that has already been loaded, to which GDB attached
to later. The only way to disable this randomization is by setting the kernel setting
`/proc/sys/kernel/randomize_va_space` to 0..
