## Command `gef-remote`

[`target remote`](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Debugging.html#Remote-Debugging)
is the traditional GDB way of debugging process or system remotely. However this command by itself
does a limited job (80's bandwith FTW) to collect more information about the target, making the
process of debugging more cumbersome. GEF greatly improves that state with the `gef-remote` command.

📝 **Note**: If using GEF, `gef-remote` **must** be your way or debugging remote processes, never
`target remote`. Maintainers will provide minimal support or help if you decide to use the
traditional `target remote` command. For many reasons, you **should not** use `target remote` alone
with GEF. It is still important to note that the default `target remote` command has been
overwritten by a minimal copy `gef-remote`, in order to make most tools relying on this command work.

`gef-remote` can function in 2 ways:

-  `remote` which is meant to enrich use of GDB `target remote` command, when connecting to a "real"
  gdbserver instance
-  `qemu-mode` when connecting to GDB stab of either `qemu-user` or `qemu-system`.

The reason for this difference being that Qemu provides *a lot* less information that GEF can
extract to enrich debugging. Whereas GDBServer allows to download remote file (therefore allowing to
create a small identical environment), GDB stub in Qemu does not support file transfer. As a
consequence, in order to use GEF in qemu mode, it is required to provide the binary being debugged.
GEF will create a mock (limited) environment so that all its most useful features are available.

### Remote mode

#### `remote`

If you want to remotely debug a binary that you already have, you simply need to tell to `gdb` where
to find the debug information.

For example, if we want to debug `uname`, we do on the server:

```text
$ gdbserver  :1234 /tmp/default.out
Process /tmp/default.out created; pid = 258932
Listening on port 1234
```

![gef-remote-1](https://i.imgur.com/Zc4vnBd.png)

On the client, when the original `gdb` would use `target remote`, GEF's syntax is roughly similar
(shown running in debug mode for more verbose output, but you don't have to):

```text
$ gdb -ex 'gef config gef.debug 1'
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 10.2 using Python engine 3.8
gef➤ gef-remote localhost 1234
[=] [remote] initializing remote session with localhost:1234 under /tmp/tmp8qd0r7iw
[=] [remote] Installing new objfile handlers
[=] [remote] Enabling extended remote: False
[=] [remote] Executing 'target remote localhost:1234'
Reading /tmp/default.out from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /tmp/default.out from remote target...
Reading symbols from target:/tmp/default.out...
[=] [remote] in remote_objfile_handler(target:/tmp/default.out))
[=] [remote] downloading '/tmp/default.out' -> '/tmp/tmp8qd0r7iw/tmp/default.out'
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
[=] [remote] in remote_objfile_handler(/usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug))
[=] [remote] in remote_objfile_handler(target:/lib64/ld-linux-x86-64.so.2))
[=] [remote] downloading '/lib64/ld-linux-x86-64.so.2' -> '/tmp/tmp8qd0r7iw/lib64/ld-linux-x86-64.so.2'
[=] [remote] in remote_objfile_handler(system-supplied DSO at 0x7ffff7fcd000))
[*] [remote] skipping 'system-supplied DSO at 0x7ffff7fcd000'
0x00007ffff7fd0100 in _start () from target:/lib64/ld-linux-x86-64.so.2
[=] Setting up as remote session
[=] [remote] downloading '/proc/258932/maps' -> '/tmp/tmp8qd0r7iw/proc/258932/maps'
[=] [remote] downloading '/proc/258932/environ' -> '/tmp/tmp8qd0r7iw/proc/258932/environ'
[=] [remote] downloading '/proc/258932/cmdline' -> '/tmp/tmp8qd0r7iw/proc/258932/cmdline'
[...]
```

And finally breaking into the program, showing the current context:

![gef-remote](https://i.imgur.com/IfsRDvK.png)

You will also notice the prompt has changed to indicate the debugging mode is now "remote". Besides
that, all of GEF features are available:

![gef-remote-command](https://i.imgur.com/05epyX6.png)

#### `remote-extended`

Extended mode works the same as `remote`. Being an extended session, gdbserver has not spawned or
attached to any process. Therefore, all that's required is to add the `--pid` flag when calling
`gef-remote`, along with the process ID of the process to debug.

### Qemu mode

Qemu mode of `gef-remote` allows to connect to the [Qemu GDB
stub](https://qemu-project.gitlab.io/qemu/system/gdb.html) which allows to live debug into either a
binary (`qemu-user`) or even the kernel (`qemu-system`), of any architecture supported by GEF, which
makes now even more sense 😉 And using it is very straight forward.

#### `qemu-user`

 1.  Run `qemu-x86_64 :1234 /bin/ls`
 2.  Use `--qemu-user` and `--qemu-binary /bin/ls` when starting `gef-remote`

![qemu-user](https://user-images.githubusercontent.com/590234/175072835-e276ab6c-4f75-4313-9e66-9fe5a3fd220e.png)

#### `qemu-system`

To test locally, you can use the mini image linux x64 vm
[here](https://mega.nz/file/ldQCDQiR#yJWJ8RXAHTxREKVmR7Hnfr70tIAQDFeWSYj96SvPO1k).

 1.  Run `./run.sh`
 2.  Use `--qemu-user` and `--qemu-binary vmlinuz` when starting `gef-remote`

![qemu-system](https://user-images.githubusercontent.com/590234/175071351-8e06aa27-dc61-4fd7-9215-c345dcebcd67.png)
