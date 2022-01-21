## Command vmmap ##

`vmmap` displays the target process's entire memory space mapping.

![vmmap](https://i.imgur.com/V9zMLUt.png)

Interestingly, it helps finding secret gems: as an aware reader might have
seen, memory mapping differs from one architecture to another (this is one of
the main reasons I started `GEF` in a first place). For example, you can learn
that ELF running on SPARC architectures always have their `.data` and `heap`
sections set as Read/Write/Execute.

`vmmap` accepts one argument, either a pattern to match again mapping names,
or an address to determine which section it belongs to.

![vmmap-grep](https://i.imgur.com/ZFF4QVf.png)

![vmmap-address](https://i.imgur.com/hfcs1jH.png)
