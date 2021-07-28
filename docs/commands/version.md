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
Blob Hash(/gef/rules/gef.py): 2939fbc037bca090422e12cf1b555bd58223dccb
SHA1(/gef/rules/gef.py): 6e6bfd03282a0d5b1eec5276fa57af0ccbac31c6
GDB: 9.2
GDB-Python: 3.8
```

The `Blob Hash` can be used to easily find the git commit(s) matching
this file revision (or whether it has been modified and does not match
any revision):

```
git log --oneline --find-object <BLOB_HASH>
```
