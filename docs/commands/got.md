## Command got ##

Display the current state of GOT table of the running process.

The `got` command optionally takes function names and filters 
the output displaying only the matching functions. 
```
gef➤ got
```

![gef-got](https://i.imgur.com/NHceezH.png)

The applied filter partially matches the name of the functions, so
you can do something like this.
```
gef➤ got str
gef➤ got fget
gef➤ got mem
```

![gef-got-one-filter](https://i.imgur.com/mqlWW0x.png)

Example of multiple partial filters:
```
gef➤ got str get
```

![gef-got-multi-filter](https://i.imgur.com/Z4W9s56.png)