## Command `print-format`

The command `print-format` (alias `pf`) will dump an arbitrary location as an array of bytes
following the format specified. Currently, the output formats supported are

-  Python (`py` - default)
-  C (`c`)
-  Assembly (`asm`)
-  Javascript (`js`)
-  Hex string (`hex`)
-  For patch byte command or GDB $_gef[N] byte access (`bytearray`)

```text
gef➤  print-format -h
[+] print-format [--lang LANG] [--bitlen SIZE] [(--length,-l) LENGTH] [--clip] LOCATION
    --lang LANG specifies the output format for programming language (available: ['py', 'c', 'js', 'asm', 'hex'], default 'py').
    --bitlen SIZE specifies size of bit (possible values: [8, 16, 32, 64], default is 8).
    --length LENGTH specifies length of array (default is 256).
    --clip The output data will be copied to clipboard
    LOCATION specifies where the address of bytes is stored.
```

For example this command will dump 10 bytes from `$rsp` and copy the result to the clipboard.

```text
gef➤  print-format --lang py --bitlen 8 -l 10 --clip $rsp
[+] Copied to clipboard
buf = [0x87, 0xfa, 0xa3, 0xf7, 0xff, 0x7f, 0x0, 0x0, 0x30, 0xe6]
```

These commands copy the first 10 bytes of $rsp+8 to $rip:

```text
gef➤  print-format --lang bytearray -l 10 $rsp+8
Saved data b'\xcb\xe3\xff\xff\xff\x7f\x00\x00\x00\x00'... in '$_gef0'
gef➤  display/x $_gef0[5]
4: /x $_gef0[5] = 0x7f
gef➤  patch byte $rip $_gef0
```

Very handy to copy-paste-execute shellcodes/data from different memory regions.
