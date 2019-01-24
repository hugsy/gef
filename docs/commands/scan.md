## Command scan ##

`scan` Search for addresses that are located in a memory mapping (haystack) that
belonging to another (needle).

![scan-example](https://i.imgur.com/Ua0VXRY.png)

`scan` requires two arguments, the first is the memory section that will be
searched and the second is what will be searched for. The arguments are grepped
against the processes memory mappings (just like [vmmap](docs/commands/vmmap.md)
to determine the memory ranges to search.

To check mappings without a path associated, an address range (start-end) can be used.

![scan-address](https://i.imgur.com/ExJC2p7.png)