## Command pattern ##

This command will create or search a [De
Bruijn](https://en.wikipedia.org/wiki/De_Bruijn_sequence) cyclic pattern to
facilitate determining offsets in memory.

It should be noted that for better compatibility, the algorithm implemented in
`GEF` is the same as the one in `pwntools`, and can therefore be used in
conjunction.

### create

The sub-command `create` allows to create a new pattern:

```
gef➤  pattern create 128
[+] Generating a pattern of 128 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab
[+] Saved as '$_gef0'
```

Ths pattern can be used as as input later on. To generate this input, `GEF`
takes into account the size of architecture (16, 32 or 64 bits), to generate
it.

The equivalent command with `pwntools` is
```python
from pwn import *
p = cyclic(128, n=8)
```
where `n` is the number of bytes of the architecture (8 for 64 bits, 4 for 32).


### search

The `search` sub-command seeks the value given as argument, trying to find it in
the De Bruijn sequence
```
gef➤  pattern search 0x6161616161616167
[+] Searching '0x6161616161616167'
[+] Found at offset 48 (little-endian search) likely
[+] Found at offset 41 (big-endian search)
```

Note that registers can also be passed as values:
```
gef➤  pattern search $rbp
[+] Searching '$rbp'
[+] Found at offset 32 (little-endian search) likely
[+] Found at offset 25 (big-endian search)
```
