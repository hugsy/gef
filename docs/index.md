# GEF - GDB Enhanced Features #

[![ReadTheDocs](https://readthedocs.org/projects/gef/badge/?version=latest)](https://gef.readthedocs.org/en/latest/) [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/master/LICENSE) [![Python 2](https://img.shields.io/badge/Python-2-brightgreen.svg)](https://github.com/hugsy/gef/) [![Python 3](https://img.shields.io/badge/Python-3-brightgreen.svg)](https://github.com/hugsy/gef/) [![IRC](https://img.shields.io/badge/freenode-%23%23gef-yellowgreen.svg)](https://webchat.freenode.net/?channels=##gef) [![Build Status](https://travis-ci.org/hugsy/gef.svg?branch=master)](https://travis-ci.org/hugsy/gef)

`GEF` is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC to
make GDB cool again for exploit dev. It is aimed to be used mostly by exploiters
and reverse-engineers, to
provide additional features to GDB using the Python API to assist during the
process of dynamic analysis and exploit development.

`GEF` fully relies on GDB API and other Linux-specific sources of information
(such as `/proc/<pid>`). As a consequence, some of the features might not work on
custom or hardened systems such as GrSec.

It has full support for both Python2 and Python3 indifferently (as more and more
distros start pushing `gdb` compiled with Python3 support).

![gef-context](https://i.imgur.com/Fl8yuiO.png)

*Some* of `GEF` features include:

  * **One** single GDB script.
  * **No** dependencies, `GEF` is battery-included and is literally installable
    within 5 seconds.
  * Provides more than **50** commands to drastically change your experience in
    GDB.
  * Works consistently on both Python2 and Python3.
  * Built around an architecture abstraction layer, so all commands work in any
    GDB-supported architecture (x86-32/64, ARMv5/6/7, AARCH64, SPARC, MIPS,
    PowerPC, etc.).


## Quick start ##

### Install ###

Simply make sure you have [GDB 7.x+](https://www.gnu.org/s/gdb).

```bash
# via the install script
$ wget -q -O- https://github.com/hugsy/gef/raw/master/gef.sh | sh

# manually
$ wget -q -O ~/.gdbinit-gef.py https://github.com/hugsy/gef/raw/master/gef.py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

Then just start playing (for local files):

```bash
$ gdb -q /path/to/my/bin
gef➤  gef help
```

Or (for remote debugging):

```bash
remote:~ $ gdbserver 0.0.0.0:1234 /path/to/file
Running as PID: 666
```

And:

```bash
local:~ $ gdb -q
gef➤  gef-remote -t your.ip.address:1234 -p 666
```

### Update ###

If your host/VM is connected to the Internet, you can update `gef` easily to the latest version (even without `git` installed). with `python /path/to/gef.py --update`

For example:

```bash
$ python ~/.gdbinit-gef.py --update
Updated
```

If no updates are available, `gef` will respond `No update` instead.

## Screenshots ##

This shows a few examples of new features available to you when installing
`GEF`, with the supported architecture.

#### Emulating code in GDB via Unicorn-Engine (x86-64) ####

![gef-x86](https://i.imgur.com/emhEsol.png)

#### Displaying ELF information, memory mapping and using Capstone/Keystone integration (ARM v6) ####

![gef-arm](http://i.imgur.com/qOL8CnL.png)

#### Automatic dereferencing of registers values and identifying binary protections (PowerPC) ####

![gef-ppc](https://i.imgur.com/IN6x6lw.png)

#### Showing current context and heap information (MIPS) ####

![gef-mips](https://i.imgur.com/dBaB9os.png)

#### Playing with Capstone engine (SPARC v9) ####

![gef-sparc](https://i.imgur.com/VD2FpDt.png)


## Dependencies ##

There are none: `GEF` works out of the box! However, to enjoy all the coolest
features, it is **highly** recommended to install:

- [`capstone`](https://github.com/aquynh/capstone)
- [`keystone`](https://github.com/keystone-engine/keystone): requires `cmake`
- [`unicorn`](https://github.com/unicorn-engine/unicorn)
- [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget)
- [`Ropper`](https://github.com/sashs/ropper)


### Capstone/Keystone/Unicorn ###

`GEF` greatly enhances the capabilities of GDB thanks to a full integration of
the following libraries:
   - [`capstone`](https://github.com/aquynh/capstone)
   (by [Nguyen Anh Quynh](https://github.com/aquynh)) is an alternative disassembly
   engine, and [`keystone`](https://github.com/keystone-engine/keystone) is an
   (arguably the best) assembly engine.
   - [`keystone`](https://github.com/keystone-engine/keystone) allows us to
   generate opcodes, which can, for example, then be used as part of a
   shellcode.

![gef-shellcoder](https://i.imgur.com/BPdtr2D.png)

   - [`unicorn`](https://github.com/unicorn-engine/unicorn) (also written
   by [Nguyen Anh Quynh](https://github.com/aquynh)) is a lightweight Qemu-based
   framework to emulate any architecture currently supported by `GDB` (and even
   some more).


#### One-liners ####

For a quick installation, use the `pip` packaged version:

```bash
$ pip2 install capstone unicorn keystone-engine  # for Python2.x
$ pip3 install capstone unicorn keystone-engine  # for Python3.x
```

#### Manual installation ####
You can use `pip` to simply and quickly install it.

`capstone` and `keystone` are under very active development and improvement, so it is recommended to compile and install them from git.
```bash
$ git clone https://github.com/keystone-engine/keystone.git
$ mkdir -p keystone/build && cd keystone/build
$ ../make-share.sh
$ sudo make install
$ sudo ldconfig
$ cd ../bindings/python && sudo ./setup.py build && sudo ./setup.py install
```

`capstone` provides an alternative to the `gdb` disassembler, which could be
useful specifically when dealing with complex/uncommon instructions.


Install is simple through `pip`, but to get the latest features from it,
installation from the repository is recommended:
```bash
$ git clone https://github.com/unicorn-engine/unicorn.git && cd unicorn && ./make.sh && sudo ./make.sh install
```

`unicorn` integration in `gef` allows to emulate the behaviour to specific instructions (or block of instructions) based on the runtime context, without actually running it, and therefore sparing the trouble of saving the context/running the new context/restoring the old context. Additionally, `gef` can generate a standalone `unicorn` Python script, if you want/need to reproduce steps outside the debugger.


### ROPGadget ###

[`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) (written by [Jonathan Salwan](https://github.com/JonathanSalwan)) is simply the best cross-platform ROP gadget finder. It has been totally integrated inside `gef` to benefit of all of its awesomeness.
```bash
$ pip[23] install ropgadget
```

### Ropper ###

[`Ropper`](https://github.com/sashs/ropper) (written by [Sascha Schirra](https://github.com/sashs)) is another gadget finder. It supports opening multiple files and provides an awesome search option to find accurate gadgets.
```bash
$ pip[23] install ropper
```

### One-liner

Some of the optional dependencies can be installed using Python package
installer, `pip`. Simply run this
```bash
$ pip[23] install ropgadget ropper capstone
```

## But why not PEDA? ##

Yes! Why not?! [PEDA](https://github.com/longld/peda) is a fantastic tool to
do the same, but **only** works for x86-32 or x86-64x whereas `GEF` supports
all the architecture supported by `GDB` (currently x86, ARM, AARCH64, MIPS,
PowerPC, SPARC) but is designed to integrate new architectures very easily as
well!


## Bugs & Feedbacks ##

To discuss `gef`, `gdb`, exploitation or other topics, feel free to join the
`##gef` channel on the Freenode IRC network. You can also to me (`hugsy`) via the
channel. For those who do not have an IRC client (like `weechat` or `irssi`),
simply [click here](https://webchat.freenode.net/?channels=##gef).

For bugs or feature requests, just
go [here](https://github.com/hugsy/gef/issues) and provide a thorough description
if you want help.


## Contribution ##

`gef` was created and maintained by myself,
[`@_hugsy_`](https://twitter.com/_hugsy_), but kept fresh thanks to [all
the contributors](https://github.com/hugsy/gef/graphs/contributors).

Or if you just like the tool, feel free to drop a simple *"thanks"* on IRC,
Twitter or other, it is **always** very appreciated.


## Open-Source Rewards ##

I love Open-Source, and just like
my [other projects](https://proxenet.readthedocs.io/en/latest/#contributing)
I've decided to offer a :beer: 4 :bug: (a.k.a *beer4bugs*) bounty for
`GEF`, to thank everybody who helps keeping the project living and always
better.

The rule is simple, provide a (substantial) contribution to `GEF`, such as:

   1. Submitting a Pull-Request for a new feature/command.
   1. Submitting a Pull-Request for a new architecture support.
   1. Or sending a relevant issue request (like a bug, crash, or else).

Poke me on the IRC `##gef` channel about it, and next time we meet in person
(like at a conference), I'll be happy to pay you a beer.

I do also accept beers if you think that the tool is cool! :wink:

Cheers :beers:

# Happy Hacking #
