## Command `got`

Display the current state of GOT table of the running process.

The `got` command optionally takes function names and filters the output displaying only the
matching functions.

```text
gef➤ got [--all] [filters]
```

`--all` Print the GOT for all shared objects in addition to the executable file

![gef-got](docs/assets/images/gef-got.png)

The applied filter partially matches the name of the functions, so you can do something like this.

```text
gef➤ got str
gef➤ got print
gef➤ got read
```

![gef-got-one-filter](docs/assets/images/gef-got-one-filter.png)

Example of multiple partial filters:

```text
gef➤ got str get
```

![gef-got-multi-filter](docs/assets/images/gef-got-multi-filter.png)

```text
gef➤ got --all str get
```

Print relocatable symbols matching "str" or "get" in the executable and all shared object files.

**Note**: Because gdbserver does not canonicalize paths, the --all option does not work correctly
for remote debugging.  See gdb bug [23764](https://sourceware.org/bugzilla/show_bug.cgi?id=23764)
