## Command print-format ##

The command `print-format` (alias `pf`) will dump an arbitrary location as an array of bytes following the format specified. Currently, the output formats supported are

 - Python (`py` - default)
 - C (`c`)
 - Assembly (`asm`)
 - Javascript (`js`)
 - Hex string (`hex`)


```
gef➤  print-format -h
[+] print-format [--lang LANG] [--bitlen SIZE] [(--length,-l) LENGTH] [--clip] LOCATION
    --lang LANG specifies the output format for programming language (available: ['py', 'c', 'js', 'asm', 'hex'], default 'py').
    --bitlen SIZE specifies size of bit (possible values: [8, 16, 32, 64], default is 8).
    --length LENGTH specifies length of array (default is 256).
    --clip The output data will be copied to clipboard
    LOCATION specifies where the address of bytes is stored.
```

For example this command will dump 10 bytes from `$rsp` and copy the result to the clipboard.

```
gef➤  print-format --lang py --bitlen 8 -l 10 --clip $rsp
[+] Copied to clipboard
buf = [0x87, 0xfa, 0xa3, 0xf7, 0xff, 0x7f, 0x0, 0x0, 0x30, 0xe6]
```
