## Command `got`

Display the current state of GOT table of the running process.

The `got` command optionally takes function names and filters the output displaying only the
matching functions.

```text
gef➤ got
```

![gef-got](https://i.imgur.com/554ebM3.png)

The applied filter partially matches the name of the functions, so you can do something like this.

```text
gef➤ got str
gef➤ got print
gef➤ got read
```

![gef-got-one-filter](https://i.imgur.com/IU715CG.png)

Example of multiple partial filters:

```text
gef➤ got str get
```

![gef-got-multi-filter](https://i.imgur.com/7L2uLt8.png)
