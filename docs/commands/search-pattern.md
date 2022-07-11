## Command `search-pattern`

`gef` allows you to search for a specific pattern at runtime in all the segments
of your process memory layout. The command `search-pattern`, alias `grep`, aims
to be straight-forward to use:
```
gef➤  search-pattern MyPattern
```

![grep](https://i.imgur.com/YNzsFvk.png)

It will provide an easily understandable to spot occurrences of the specified
pattern, including the section it/they was/were found, and the permission
associated to that section.

`search-pattern` can also be used to search for addresses. To do so, simply
ensure that your pattern starts with `0x` and is a valid hex address. For
example:

```
gef➤  search-pattern 0x4005f6
```

![grep-address](https://i.imgur.com/dg1gUB5.png)

The `search-pattern` command can also be used as a way to search for
cross-references to an address. For this reason, the alias `xref` also points
to the command `search-pattern`.  Therefore the command above is equivalent to
`xref 0x4005f6` which makes it more intuitive to use.

### Searching in a specific range ###
Sometimes, you may need to search for a very common pattern. To limit the search space, you can also specify an address range or the section to be checked.

```
gef➤  search-pattern 0x4005f6 little libc
gef➤  search-pattern 0x4005f6 little 0x603100-0x603200
```
### Searching in a specific range using regex ###
Sometimes, you may need an advanced search using regex. Just use --regex arg.

Example: how to find null-end-printable(from x20-x7e) C strings (min size >=2 bytes) with a regex:

```
gef➤  search-pattern --regex 0x401000 0x401500 ([\\x20-\\x7E]{2,})(?=\\x00)

```
