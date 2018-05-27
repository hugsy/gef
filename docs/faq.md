# Frequently Asked Questions #

## Why use GEF over PEDA? ##

[PEDA](https://github.com/longld/peda) is a fantastic tool that provides similar
commands to make the exploitation development process smoother.

However, PEDA suffers from a major drawbacks, which the code is too
fundamentally linked to Intel architectures (x86-32 and x86-64). On the other
hand, GEF not only supports all the architecture supported by GDB (currently
x86, ARM, AARCH64, MIPS, PowerPC, SPARC) but is designed to integrate new
architectures very easily as well!

Also, PEDA development has been quite idle for a few years now, and many new
interesting features a debugger can provide simply do not exist.

## What if my GDB is < 7.7 ? ##

GDB was introduced with its Python support early 2011 with the release of
GDB 7. A (very) long way has gone since and the Python API has been massively
improved, and GEF is taking advantage of them to provide the coolest features
with as little performance impact as possible.

Therefore, it is highly recommended to run GEF with the latest version of
GDB. However, all functions should work on a GDB 7.7 and up. If not, send
a [bug report](https://github.com/hugsy/gef/issues) and provide as much details
as possible.

If you are running an obsolete version, GEF will show a error and message and
exit. You can still use GDB the normal way.

Some pre-compiled static binaries for both recent GDB and GDBServer can be
downloaded from the [`gdb-static`](https://github.com/hugsy/gdb-static) repository.

_Note_: although some Ubuntu versions are marked as version 7.7 they are
actually compiled with some missing features that will make `GEF` complain of an
error. Before lodging a bug report, make sure to update your GDB (via APT is
fine), or better install `gdb-multiarch` (the package `gdb64` will work as well,
but is considered obsolete).

## I cannot get GEF setup!! ##

GEF will work on any GDB 7.7+ compiled with Python support. You can view
that commands that failed to load using `gef missing`, but this will not affect
GEF generally.

If you experience problems setting it up on your host, first go to the
IRC channel [`freenode##gef`](https://webchat.freenode.net/?channels=##gef) for
that. You will find great people there willing to help.

Note that the GitHub issue section is to be used to **report bugs** and
**GEF issues** (like unexpected crash, improper error handling, weird edge case,
etc.), not a place to ask for help.

But fear not, GDB 7.7 corresponds to the latest packaged version of Ubuntu
14.04. Any version higher or equal will work just fine. So you might actually
only need to run `apt install gdb` to get the full-force of GEF.

## I get a SegFault when starting GDB with GEF ##

A long standing bug in the `readline` library can make `gef` crash GDB
when displaying certain characters (SOH/ETX). As a result, this would SIGSEGV
GDB as `gef` is loading, a bit like this:

```
root@debian-aarch64:~# gdb -q ./test-bin-aarch64
GEF ready, type `gef' to start, `gef config' to configure
53 commands loaded, using Python engine 3.4
[*] 5 commands could not be loaded, run `gef missing` to know why.
[+] Configuration from '/root/.gef.rc' restored
Reading symbols from ./bof-aarch64...(no debugging symbols found)...done.
Segmentation fault (core dumped)
```

If so, this can be fixed easily by setting the `gef.readline_compat` variable to
`True` in the `~/.gef.rc` file. Something like this:

```
root@debian-aarch64:~# nano ~/.gef.rc
[...]
[gef]
readline_compat = True
```

You can now use all features of `gef` even on versions of GDB compiled against
old `readline` library.


## Does GEF prevent the use of other GDB plugins? ##

Definitely not! You can use any other GDB plugin on top of it for an even better
debugging experience.

Some interesting plugins highly recommended too:

- [!exploitable](https://github.com/jfoote/exploitable/)
- [Voltron](https://github.com/snare/voltron)

![voltron](https://pbs.twimg.com/media/CsSkk0EUkAAJVPJ.jpg:large)
Src: [@rick2600: terminator + gdb + gef + voltron cc: @snare @_hugsy_](https://twitter.com/rick2600/status/775926070566490113)


## GEF says missing modules, but I'm sure I've installed them, what's up with that? ##

99.999% of the time, this happens because the module(s) were **not** installed
for the Python version GDB is compiled to work with! For example, GDB is
compiled for Python3 support, but the module(s) was(were) installed using `pip2`
(and therefore Python2).

To verify this, you can simply start GDB with GEF, which will show you the
Python version currently supported by your GDB, or run the command:

```bash
$ gdb -q -nx -ex 'pi print (sys.version)' -ex quit
3.5.2+ (default, Dec 13 2016, 14:16:35)
[GCC 6.2.1 20161124]
```

It immediately shows that GDB was compiled for Python3. You have to install the
modules (such as `capstone`, `keystone`, etc.) for this version and it will
work, guaranteed.

And if this does not work, it is simply that the modules was not installed
properly. To avoid incorrect behavior, if importing the Python module fails,
GEF will simply discard altogether the command that uses it, and it will be
shown when running the `gef missing` command.

To see the proper stacktrace, simply open a Python interpreter and try importing
the module. This will show you an error.


## I want to contribute, where should I head first? ##

I would suggest thoroughly reading this documentation, just having a look to the
[CONTRIBUTE](https://github.com/hugsy/gef/blob/master/.github/CONTRIBUTING.md)
file of the project to give you pointers.

Also a good thing would be to join the `##gef` IRC channel
on [Freenode](https://webchat.freenode.net/?channels=##gef) to get in touch with
the people involved/using it.


## I think I've found a bug, how can I help fixing it? ##

`gef` is only getting better through people (like you!) using it, but most
importantly reporting unexpected behavior.

In most locations, Python exceptions will be properly intercepted. If not, `gef`
wraps all commands with a generic exception handler, to disturb as little as
possible your debugging session. If it happens, you'll only get to see a message
like this:
![gef-exception](http://i.imgur.com/J7dUnXV.png)

By switching to debug mode, `gef` will give much more information:
```
gef➤  gef config gef.debug 1
```
![gef-debug](http://i.imgur.com/SGe8oFF.png)

If you think fixing it is in your skills, then send a [Pull
Request](https://github.com/hugsy/gef/pulls) with your patched version,
explaining your bug, and what was your solution for it.

Otherwise, you can open an [issue](https://github.com/hugsy/gef/issues), give a
thorough description of your bug and copy/paste the content from above. This
will greatly help for solving the issue.


## I get weird issues/characters using GDB + Python3, what's up? ##

Chances are you are not using UTF-8. Python3
is [highly relying on UTF-8](http://www.diveintopython3.net/strings.html) to
display correctly characters of any alphabet
and
[also some cool emojis](http://unicode.org/emoji/charts/full-emoji-list.html). When
GDB is compiled with Python3, GEF will assume that your current charset is UTF-8
(for instance, `en_US.UTF-8`). Use your `$LANG` environment variable to tweak
this setting.

In addition, some unexpected results were observed when your local is not set to
English. If you aren't sure, simply run `gdb` like this:

```
$ LC_ALL=en_US.UTF-8 gdb /path/to/your/binary
```

## GDB crashes on ARM memory corruption with `gdb_exception_RETURN_MASK_ERROR` ##

This issue is **NOT** GEF related, but GDB's, or more precisely some versions of
GDB packaged with Debian/Kali for ARM

>
> Original Issue and Mitigation
>
> gdb version 7.12, as distributed w/ Raspbian/Kali rolling (only distro's
> tested,) throws an exception while disassembling ARM binaries when using gef.
> This is not a gef problem, this is a gdb problem. gef is just the tool that
> revealed the gdb dain bramage! (The issue was not observed using vanilla
> gdb/peda/pwndbg) This issue was first noted when using si to step through a
> simple ARM assembly program (noted above) when instead of exiting cleanly,
> gdb's disassembly failed with a SIGABRT and threw an exception:
>
>  `gdb_exception_RETURN_MASK_ERROR`
>
> This turns out to be a known problem (regression) with gdb, and affects
> gef users running the ARM platform (Raspberry Pi).
>
> The mitigation is for ARM users to compile gdb from source and run the latest
> version, 8.1 as of this writing.
>

**Do not file an issue**, again it is **NOT** a bug from GEF, or neither from GDB
Python API. Therefore, there is nothing GEF's developers can do about that. The
correct solution as mentioned above is to recompile your GDB with a newer
(better) version.

The whole topic was already internally discussed, so please refer to
the [issue #206](https://github.com/hugsy/gef/issues/206) for the whole story.
