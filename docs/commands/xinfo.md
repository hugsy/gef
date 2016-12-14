## Command xinfo ##

`xinfo`, `vmmap` and `xfiles` display a comprehensive and human-friendly memory
mapping of either the process or a specific location.

![vmmap-example](https://i.imgur.com/iau8SwS.png)

Interestingly, it helps finding secret gems: as an aware reader might have seen,
memory mapping differs from one architecture to another (this is one of the main
reasons I started `GEF` in a first place). For example, you can learn that
ELF running on SPARC architectures always have their `.data` and `heap` sections set as
Read/Write/Execute.

![xinfo-example](https://pbs.twimg.com/media/CCSW9JkW4AAx8gD.png:large)

**Important note** : `gef` will as much as possible automatically refresh its
own cache to avoid relying on obsolete information of the debugged
process. However, in some dodgy scenario, `gef` might fail detecting some new
events making its cache partially obsolete. If you notice an inconsistency on
your memory mapping, you might want to force `gef` flushing its cache and
fetching brand new data, by running the command `reset-cache`.



