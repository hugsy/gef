## Command heap ##

The `heap` command provides information on the heap chunk specified as argument. For
the moment, it only supports GlibC heap format (see
[this link](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)
for `malloc` structure information). Syntax to the subcommands is straight forward:

```
gef➤ heap <sub_commands>
```

### `heap chunks` command ###

Displays all the chunks from the `heap` section of the current arena.

```
gef➤ heap chunks
```

![heap-chunks](https://i.imgur.com/y90SfKH.png)

To select from which arena to display chunks either use the `heap set-arena`
command or provide the base address of the other arena like this:

```
gef➤ heap chunks [arena_address]
```

![heap-chunks-arena](https://i.imgur.com/y1fybRx.png)

In order to display the chunks of all the available arenas at once use

```
gef➤ heap chunks -a
```

![heap-chunks-all](https://i.imgur.com/pTjRJFo.png)

Because usually the heap chunks are aligned to a certain number of bytes in
memory GEF automatically re-aligns the chunks data start addresses to match
Glibc's behavior. To be able to view unaligned chunks as well, you can disable
this with the `--allow-unaligned` flag. Note that this might result in
incorrect output.

### `heap chunk` command ###

This command gives visual information of a Glibc malloc-ed chunked. Simply
provide the address to the user memory pointer of the chunk to show the
information related to a specific chunk:

```
gef➤ heap chunk [address]
```

![heap-chunk](https://i.imgur.com/WXpHR58.png)

Because usually the heap chunks are aligned to a certain number of bytes in
memory GEF automatically re-aligns the chunks data start addresses to match
Glibc's behavior. To be able to view unaligned chunks as well, you can disable
this with the `--allow-unaligned` flag. Note that this might result in
incorrect output.


There is an optional `number` argument, to specify the number of chunks printed by this command. To do so, simply provide the `--number` argument:

```
gef➤ heap chunk --number 6 0x4e5400
Chunk(addr=0x4e5400, size=0xd0, flags=PREV_INUSE)
Chunk(addr=0x4e54d0, size=0x1a0, flags=PREV_INUSE)
Chunk(addr=0x4e5670, size=0x200, flags=PREV_INUSE)
Chunk(addr=0x4e5870, size=0xbc0, flags=PREV_INUSE)
Chunk(addr=0x4e6430, size=0x330, flags=PREV_INUSE)
Chunk(addr=0x4e6760, size=0x4c0, flags=PREV_INUSE)

```

### `heap arenas` command ###

Multi-threaded programs have different arenas, and the knowledge of the
`main_arena` is not enough. `gef` therefore provides the `arena` sub-commands
to help you list all the arenas allocated in your program **at the moment you
call the command**.

![heap-arenas](https://i.imgur.com/RUTiADa.png)

### `heap set-arena` command ###

In cases where the debug symbol are not present (e.g. statically stripped
binary), it is possible to instruct GEF to find the `main_arena` at a different
location with the command:

```
gef➤ heap set-arena [address]
```

If the arena address is correct, all `heap` commands will be functional, and use
the specified address for `main_arena`.

### `heap bins` command ###

Glibc uses bins for keeping tracks of `free`d chunks. This is because making
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
- `tcachebins`

#### `heap bins fast` command ####

When exploiting heap corruption vulnerabilities, it is sometimes convenient to
know the state of the `fastbinsY` array.

The `fast` sub-command helps by displaying the list of fast chunks in this
array. Without any other argument, it will display the info of the `main_arena`
arena. It accepts an optional argument, the address of another arena (which you
can easily find using `heap arenas`).

```
gef➤ heap bins fast
──────────────────────── Fastbins for arena 0x7ffff7fb8b80 ────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x555555559380, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

#### Other `heap bins X` command ####

All the other subcommands (with the exception of `tcache`) for the `heap bins`
work the same way as `fast`. If no argument is provided, `gef` will fall back
to `main_arena`. Otherwise, it will use the address pointed as the base of the
`malloc_state` structure and print out information accordingly.

#### `heap bins tcache` command ####

Modern versions of `glibc` use `tcache` bins to speed up multithreaded
programs.  Unlike other bins, `tcache` bins are allocated on a per-thread
basis, so there is one set of `tcache` bins for each thread.

```
gef➤ heap bins tcache [all] [thread_ids...]
```

Without any arguments, `heap bins tcache` will display the `tcache` for the
current thread. `heap bins tcache all` will show the `tcache`s for every
thread, or you can specify any number of thread ids to see the `tcache` for
each of them. For example, use the following command to show the `tcache` bins
for threads 1 and 2.

```
gef➤ heap bins tcache 1 2
```
