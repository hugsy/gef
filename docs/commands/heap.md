## Command heap ##

The `heap` command provides information on the heap chunk specified as argument. For
the moment, it only supports GlibC heap format (see
[this link](http://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)
for `malloc` structure information). Syntax to the subcommands is straight forward:

```
gef➤ heap <sub_commands>
```


### `heap chunks` command ###

Displays all the chunks from the `heap` section.

```
gef➤ heap chunks
```

In some cases, the allocation will start immediately from start of the page. If
so, specify the base address of the first chunk as follow:

```
gef➤ heap chunks <LOCATION>
```

![heap-chunks](https://i.imgur.com/2Ew2fA6.png)


### `heap chunk` command ###

This command gives visual information of a Glibc malloc-ed chunked. Simply
provide the address to the user memory pointer of the chunk to show the
information related to a specific chunk:

```
gef➤ heap chunk <LOCATION>
```

![heap-chunk](https://i.imgur.com/SAWNptW.png)



### `heap arenas` command ###

Multi-threaded programs have different arenas, and the knowledge of the
`main_arena` is not enough. `gef` therefore provides the `arena` sub-commands
to help you list all the arenas allocated in your program **at the moment you
call the command**.

![heap-arenas](https://i.imgur.com/ajbLiCF.png)



### `heap set-arena` command ###

In cases where the debug symbol are not present (e.g. statically stripped
binary), it is possible to instruct GEF to find the `main_arena` at a different
location with the command:

```
gef➤ heap set-arena <LOCATION>
```

If the arena address is correct, all `heap` commands will be functional, and use
the specified address for `main_arena`.


### `heap bins` command ###

Glibc uses bints for keeping tracks of `free`d chunks. This is because making
allocations through `sbrk` (requiring a syscall) is costly. Glibc uses those
bins to remember formerly allocated chunks. Because bins are structured in
single or doubly linked list, I found that quite painful to always interrogate
`gdb` to get a pointer address, dereference it, get the value chunk, etc... So
I decided to implement the `heap bins` sub-command, which allows to get info
on:

   - `fastbins`
   - `bins`
      - `unsorted`
      - `small bins`
      - `large bins`


#### `heap bins fast` command ####

When exploiting heap corruption vulnerabilities, it is sometimes convenient to
know the state of the `fastbinsY` array.

The `fast` sub-command helps by displaying the list of fast chunks in this
array. Without any other argument, it will display the info of the `main_arena`
arena. It accepts an optional argument, the address of another arena (which you
can easily find using `heap arenas`).

```
gef➤ heap bins fast
[+] FastbinsY of arena 0x7ffff7dd5b20
Fastbin[0] 0x00
Fastbin[1]  →  FreeChunk(0x600310)  →  FreeChunk(0x600350)
Fastbin[2] 0x00
Fastbin[3] 0x00
Fastbin[4] 0x00
Fastbin[5] 0x00
Fastbin[6] 0x00
Fastbin[7] 0x00
Fastbin[8] 0x00
Fastbin[9] 0x00
```


#### Other `heap bins X` command ####

All the other subcommands for the `heap bins` work the same way as `fast`. If
no argument is provided, `gef` will fall back to `main_arena`. Otherwise, it
will use the address pointed as the base of the `malloc_state` structure and
print out information accordingly.
