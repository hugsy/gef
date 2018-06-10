## Command syscall-args ##

Often it is troublesome to have to refer to syscall tables everytime we encounter a system call instruction.
`gef` can be used to determine the system call being invoked and the arguments being passed to it. Requires [gef-extras](http://github.com/hugsy/gef-extras).

To use it, simply run
```
gef➤ syscall-args
```

For instance,
```
───────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$rax   : 0x0000000000000001
$rbx   : 0x0000000000000045
$rcx   : 0x00000000fbad2a84
$rdx   : 0x0000000000000045
$rsp   : 0x00007fffffffdbf8  →  0x00007ffff786f4bd  →  <_IO_file_write+45> test rax, rax
$rbp   : 0x0000555555775510  →  "alarm@192.168.0.100\t\t  how2heap\t\t\t\t\t\t\t   [...]"
$rsi   : 0x0000555555775510  →  "alarm@192.168.0.100\t\t  how2heap\t\t\t\t\t\t\t   [...]"
$rdi   : 0x0000000000000001
$rip   : 0x00007ffff78de132  →  <write+18> syscall 
$r8    : 0x0000555555783b44  →  0x0000000000000066 ("f"?)
$r9    : 0x0000000000000000
$r10   : 0x0000000000002000
$r11   : 0x00007fffffffb940  →  0x7669006666757473 ("stuff"?)
$r12   : 0x00007ffff7bab760  →  0x00000000fbad2a84
$r13   : 0x0000000000000045
$r14   : 0x00007ffff7ba6760  →  0x0000000000000000
$r15   : 0x0000000000000045
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033  $gs: 0x0000  $ss: 0x002b  $es: 0x0000  $fs: 0x0000  $ds: 0x0000  

...

gef➤  syscall-args
[+] Detected syscall write
    write(unsigned int fd, const char *buf, size_t count)
[+] Parameter       Register        Value
    fd              $rdi            0x1
    buf             $rsi            0x555555775510  →  "file1\t\t  file2\t\t\t\t\t\t\t   [...]"
    count           $rdx            0x45
```

Check this asciicast for visual example:
[![asciicast](https://asciinema.org/a/gNwy6khs3rkQAPyv1CMrFAnlf.png)](https://asciinema.org/a/gNwy6khs3rkQAPyv1CMrFAnlf)
