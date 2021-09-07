## Command version ##

Print out version information about your current gdb environment.

### Usage Examples ###

When GEF is located in a directory tracked with git:

```
gef➤  version
GEF: rev:48a9fd74dd39db524fb395e7db528f85cc49d081 (Git - clean)
SHA1(/gef/rules/gef.py): 848cdc87ba7c3e99e8129ad820c9fcc0973b1e99
GDB: 9.2
GDB-Python: 3.8
```

Otherwise the command shows the `standalone` information:

```
gef➤  version
GEF: (Standalone)
Blob Hash(/gef/rules/gef.py): f0aef0f481e8157006b26690bd121585d3befee0
SHA1(/gef/rules/gef.py): 4b26a1175abcd8314d4816f97fdf908b3837c779
GDB: 9.2
GDB-Python: 3.8
```

The `Blob Hash` can be used to easily find the git commit(s) matching
this file revision.

```
git log --oneline --find-object <BLOB_HASH>
```

If this command does not return anything then the file was most likely
modified and cannot be matched to a specific git commit.
