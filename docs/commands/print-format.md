## Command print-format ##
This command (`print-format` alias `pf`) will shows array of bytes like
programming language format. language format supported only python, c,
asm, and javascript.

Use `-h` for help
```
gef➤  print-format -h
[+] print-format [-f FORMAT] [-b BITSIZE] [-l LENGTH] [-c] [-h] LOCATION
        -f FORMAT specifies the output format for programming language, avaliable value is py, c, js, asm (default py).
        -b BITSIZE sepecifies size of bit, avaliable values is 8, 16, 32, 64 (default is 8).
        -l LENGTH specifies length of array (default is 256).
        -c The result of data will copied to clipboard
        LOCATION specifies where the address of bytes is stored.
```

For example this command will show 10 bytes in rsp and the result will copied to clipboard.

```
gef➤  print-format -f py -b 8 -l 10 -c $rsp
[+] Copied to clipboard
buf = [0x87, 0xfa, 0xa3, 0xf7, 0xff, 0x7f, 0x0, 0x0, 0x30, 0xe6]
```