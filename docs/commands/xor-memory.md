## Command xor-memory

This command is used to XOR a block of memory.

Its syntax is:
```
xor-memory <display|patch> <address> <size_to_read> <xor_key>
```

The first argument (`display` or `patch`) is the action to perform:

1. `display` will only show an hexdump of the result of the XOR-ed memory block, without writing the debuggee's memory.

        gef➤  xor display $rsp 16 1337
        [+] Displaying XOR-ing 0x7fff589b67f8-0x7fff589b6808 with '1337'
        ────────────────────────────────[ Original block ]────────────────────────────────────
        0x00007fff589b67f8     46 4e 40 00 00 00 00 00 00 00 00 00 00 00 00 00     FN@.............
        ────────────────────────────────[ XOR-ed block ]──────────────────────────────────────
        0x00007fff589b67f8     55 79 53 37 13 37 13 37 13 37 13 37 13 37 13 37     UyS7.7.7.7.7.7.7

2. `patch` will overwrite the memory with the xor-ed content.

        gef➤  xor patch $rsp 16 1337
        [+] Patching XOR-ing 0x7fff589b67f8-0x7fff589b6808 with '1337'
        gef➤  hexdump byte $rsp 16
        0x00007fff589b67f8     55 79 53 37 13 37 13 37 13 37     UyS7.7.7.7
