## Command gef-remote ##

It is possible to use `gef` in a remote debugging environment. Required files
will be automatically downloaded and cached in a temporary directory (`/tmp/gef`
on most Unix systems). Remember to manually delete the cache if you change the
target file or `gef` will use the outdated version.

### With a local copy ###

If you want to remotely debug a binary that you already have, you simply need to
tell to `gdb` where to find the debug information.

For example, if we want to debug `uname`, we do on the server:

```
$ gdbserver 0.0.0.0:1234 /bin/uname
Process /bin/uname created; pid = 32280
Listening on port 1234
```

![](https://i.imgur.com/Zc4vnBd.png)

And on the client, simply run `gdb`:

```
$ gdb /bin/uname
gef➤ target remote 192.168.56.1:1234
Process /bin/uname created; pid = 10851
Listening on port 1234
```

Or

```
$ gdb
gef➤ file /bin/uname
gef➤ target remote 192.168.56.1:1234
```

### Without a local copy ###

It is possible to use `gdb` internal functions to copy our targeted binary.

Following our previous example, if we want to debug `uname`, run `gdb` and
connect to our `gdbserver`. To be able to locate the right process in the
`/proc` structure, the command `gef-remote` requires 1 argument, the target
host and port.  The option `--pid` must be provided and indicate the process
PID on the remote host, only if the extended mode (`--is-extended-remote`)
is being used.

```
$ gdb
gef➤ gef-remote 192.168.56.1:1234
[+] Connected to '192.168.56.1:1234'
[+] Downloading remote information
[+] Remote information loaded, remember to clean '/tmp/gef/10851' when your session is over
```

As you can observe, if it cannot find the debug information, `gef` will try to
automatically download the target file and store in the local temporary
directory (on most Unix `/tmp`). If successful, it will then automatically load
the debug information to `gdb` and proceed with the debugging.

![gef-remote-autodownload](https://i.imgur.com/nLtvCxP.png)

You can then reuse the downloaded file for your future debugging sessions, use
it under IDA and such. This makes the entire remote debugging process
(particularly for Android applications) a child's game.

### Handling remote libraries ###

Often times you are missing a specific library the remote process is using.
To remedy this `gef-remote` can download remote libraries (and other files) if
the remote target supports it (and the remote gdbserver has sufficient
permissions). The `--download-lib LIBRARY` option can download a remote file
specified by its filepath. Furthermore `--download-everything` downloads all
remote libs found in the process's virtual memory map (`vmmap`).

Another issue with libraries is that even if you have the same libraries that
are used remotely they might have different filepaths and GDB can't
automatically find them and thereby can't resolve their symbols. The option
`--update-solib` adds the previously (with `--dowload-everything`) downloaded
libraries to the solib path so GDB can take full advantage of their symbols.

### QEMU-user mode ###

Although GDB through QEMU-user works, QEMU only supports a limited subset of all
commands existing in the `gdbremote` protocol. For example, commands such as
`remote get` or `remote put` (to download and upload a file from remote target,
respectively) are not supported. As a consequence, the default `remote` mode
for `gef` will not work either, as `gef` won't be able to fetch the content of
the remote procfs.

To circumvent this and still enjoy `gef` features with QEMU-user, a simple stub
can be artificially added, with the option `--qemu-mode` option of `gef-remote`.
Note that you need to set the architecture to match the target binary first:

```
$ qemu-arm -g 1234 ./my/arm/binary
$ gdb-multiarch ./my/arm/binary
gef➤  set architecture arm
gef➤  gef-remote --qemu-mode localhost:1234
```

![gef-qemu-user](https://i.imgur.com/A0xgEdR.png)

When debugging a process in QEMU both the memory map of QEMU and of the process
are being shown alongside.
