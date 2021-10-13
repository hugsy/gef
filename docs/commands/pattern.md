## Command pattern ##

This command will create or search a [De
Bruijn](https://en.wikipedia.org/wiki/De_Bruijn_sequence) cyclic pattern to
facilitate determining offsets in memory. The sequence consists of a number of
unique substrings of a chosen length.

It should be noted that for better compatibility, the algorithm implemented in
`GEF` is the same as the one in `pwntools`, and can therefore be used in
conjunction.

### create ###

```
pattern create [-h] [-n N] [length]
```

The sub-command `create` allows one create a new De Bruijn sequence. The
optional argument `n` determines the length of unique subsequences. Its default
value matches the currently loaded architecture. The `length` argument sets the
total length of the whole sequence.

```
gef➤  pattern create -n 4 128
[+] Generating a pattern of 128 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab
[+] Saved as '$_gef0'
```

The equivalent command with `pwntools` is

```python
from pwn import *
p = cyclic(128, n=8)
```

### search ###

```
pattern search [-h] [-n N] [--max-length MAX_LENGTH] [pattern]
```

The `search` sub-command seeks the `pattern` given as argument, trying to find
its offset in the De Bruijn sequence. The optional argument `n` determines the
length of unique subsequences, and it should usually match the length of
`pattern`. Using `MAX_LENGTH` the maximum length of the sequence to search in
can be adjusted.

Note that the `pattern` can be passed as a GDB symbol (such as a register name),
a string or a hexadecimal value

```
gef➤  pattern search 0x6161616161616167
[+] Searching '0x6161616161616167'
[+] Found at offset 48 (little-endian search) likely
[+] Found at offset 41 (big-endian search)
gef➤  pattern search $rbp
[+] Searching '$rbp'
[+] Found at offset 32 (little-endian search) likely
[+] Found at offset 25 (big-endian search)
gef➤  pattern search aaaaaaac
[+] Searching for 'aaaaaaac'
[+] Found at offset 16 (little-endian search) likely
[+] Found at offset 9 (big-endian search)
```
