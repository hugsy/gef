## Command heap ## 

`heap` command provides information on the heap chunk specified as argument. For
the moment, it only supports GlibC heap format (see
[this link](http://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)
for  `malloc` structure information). Syntax to the
subcommands is pretty straight forward :

```
gef➤ heap <sub_commands>
```


### `heap chunk` command ###

This command gives visual information of a Glibc malloc-ed chunked. Simply
provide the address to the user memory pointer of the chunk to show the
information related to the current chunk:

```
gef➤ heap chunk <LOCATION>
```

![heap-chunks](https://i.imgur.com/SAWNptW.png)



### `heap arenas` command ###

Multi-threaded programs have different arenas, and the only knowledge of the
`main_arena` is not enough.
`gef` therefore provides the `arena` sub-commands to help you list all the
arenas allocated in your program **at the moment you call the command**.

![heap-arena](https://i.imgur.com/ajbLiCF.png)



### `heap bins` command ###

Glibc bins are the structures used for keeping tracks of free-ed chunks. The
reason for that is that allocation (using `sbrk`) is costly. So Glibc uses those
bins to remember formely allocated chunks. Because bins are structured in single
or doubly linked list, I found that quite painful to always interrogate `gdb` to
get a pointer address, dereference it, get the value chunk, etc... So I
decided to implement in `gef` the `heap bins` sub-command, which allows to get info on:

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

All the other subcommands for the `heap bins` works the same way than `fast`. If
no argument is provided, `gef` will fall back to `main_arena`. Otherwise, it
will use the address pointed as the base of the `malloc_state` structure and
print out information accordingly.


