## Command xinfo ##

`xinfo` displays all the information known to `gef` about the specific address
given as argument:

![xinfo-example](https://i.imgur.com/x0KTAxz.png)

**Important note** : For performance reasons, `gef` caches certain results.
`gef` will try to automatically refresh its own cache to avoid relying on
obsolete information of the debugged process. However, in some dodgy scenario,
`gef` might fail detecting some new events making its cache partially obsolete.
If you notice an inconsistency on your memory mapping, you might want to force
`gef` flushing its cache and fetching brand new data, by running the command
`reset-cache`.
