## Command scan ##

`scan` Search for addresses belonging to one mapping (the needle) that are
located in another (the haystack).

![scan-example](https://i.imgur.com/4ScRvVc.png)

`scan` requires two arguments, the first is the memory section that will be
searched and the second is what will be searched for. The arguments are grepped
against the processes memory mappings (just like [vmmap](docs/commands/vmmap.md)
to determine the memory ranges to search.