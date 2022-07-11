## Command `patch`

`patch` lets you easily patch the specified values to the specified address.

```bash
gef➤ patch byte $eip 0x90
gef➤ patch string $eip "cool!"
```

These commands copy the first 10 bytes of $rsp+8 to $rip:

```
gef➤  print-format --lang bytearray -l 10 $rsp+8
Saved data b'\xcb\xe3\xff\xff\xff\x7f\x00\x00\x00\x00'... in '$_gef0'
gef➤  patch byte $rip $_gef0
```

Very handy to copy-paste-execute shellcodes/data from different memory regions.
