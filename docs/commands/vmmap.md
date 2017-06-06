## Command vmmap ##

`vmmap` displays the entire memory space mapping.

![vmmap-example](https://i.imgur.com/iau8SwS.png)

Interestingly, it helps finding secret gems: as an aware reader might have
seen, memory mapping differs from one architecture to another (this is one of
the main reasons I started `GEF` in a first place). For example, you can learn
that ELF running on SPARC architectures always have their `.data` and `heap`
sections set as Read/Write/Execute.

`vmmap` accepts one argument, a pattern to grep interesting results:

![vmmap-grep](http://i.imgur.com/ZFF4QVf.png)
