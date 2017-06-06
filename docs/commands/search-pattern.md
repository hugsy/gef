## Command search-pattern ##

`gef` allows you to search for a specific pattern at runtime in all the segments
of your process memory layout. The command `search-pattern`, alias `grep`, aims
to be straight-forward to use:
```
gef➤  search-pattern MyPattern
```

![grep](https://i.imgur.com/YNzsFvk.png)

It will provide an easily understandable to spot occurences of the specified
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
