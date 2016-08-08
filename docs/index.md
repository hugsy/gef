# GEF - GDB Enhanced Features  [![ReadTheDocs](https://readthedocs.org/projects/gef/badge/?version=latest)](https://gef.readthedocs.org/en/latest/) [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/master/LICENSE) [![Python 2](https://img.shields.io/badge/Python-2-brightgreen.svg)](https://github.com/hugsy/gef/)  [![Python 3](https://img.shields.io/badge/Python-3-brightgreen.svg)](https://github.com/hugsy/gef/)

**TL;DR**: `GEF` is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC to
make GDB cool again for exploit dev.

`GEF` is aimed to be used mostly by exploiters and reverse-engineers. It
provides additional features to GDB using the Python API to assist during the
process of dynamic analysis or exploit development.

`GEF` fully relies on GDB API and other Linux specific source of information
(such as `/proc/pid`). As a consequence, some of the features might not work on
custom or harden systems such as GrSec.
It has full support for Python2 and Python3 indifferently (as more and more
distro start pushing `gdb` compiled with Python3 support).


## Quick start

### Install
Simply make sure you're having a [GDB 7.x+](https://www.gnu.org/s/gdb).
``` bash
# via the install script
$ wget -q -O- https://github.com/hugsy/gef/raw/master/gef.sh | sh

# manually
$ wget -q -O ~/.gdbinit-gef.py https://github.com/hugsy/gef/raw/master/gef.py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

Then just start playing (for local files):
```bash
$ gdb -q /path/to/my/bin
gef> gef help
```

Or (for remote debugging)
```bash
remote:~ $ gdbserver 0.0.0.0:1234 /path/to/file
Running as PID: 666
```
And
```bash
local:~ $ gdb -q
gef> gef-remote -t your.ip.address:1234 -p 666
```

### Update

If your host/VM is connected to Internet, you can update `gef` easily to the latest version (even without `git` installed)
```bash
$ python /path/to/gef.py --update
Updated
```

For example,
```bash
$ python ~/.gdbinit-gef.py --update
Updated
```

If no updates are available, `gef` will respond `No update` instead.

## Show me

#### x86
![gef-x86](https://i.imgur.com/emhEsol.png)

#### ARM
![gef-arm](http://i.imgur.com/qOL8CnL.png)

#### PowerPC
![gef-ppc](https://i.imgur.com/IN6x6lw.png)

#### MIPS
![gef-mips](https://i.imgur.com/dBaB9os.png)

#### SPARC v9
![gef-sparc](https://i.imgur.com/VD2FpDt.png)

## Dependencies

There are none: `GEF` works out of the box! However, to enjoy all the coolest features, it is **highly** recommended to install:

- [`capstone`](https://github.com/aquynh/capstone)
- [`keystone`](https://github.com/keystone-engine/keystone)
- [`unicorn`](https://github.com/unicorn-engine/unicorn)
- [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget)
- [`Ropper`](https://github.com/sashs/ropper)

### {Cap,Key}stone
[`capstone`](https://github.com/aquynh/capstone) (by [Nguyen Anh Quynh](https://github.com/aquynh))is an alternative disassembly engine, and [`keystone`](https://github.com/keystone-engine/keystone) is an (arguably the best) assembly engine.
You can use `pip` to simply and quickly install it.
```bash
$ pip2 install capstone keystone-engine  # for Python2.x
$ pip3 install capstone keystone-engine   # for Python3.x
```

`capstone` and `keystone` are under very active development and improvement, so it is recommended to compile and install them from git.
```bash
$ git clone https://github.com/keystone-engine/keystone.git
$ mkdir -p keystone/build && cd keystone/build
$ cmake .. && make -j8
$ sudo make install
$ cd ../bindings/python && sudo make install # or sudo make install3 for Python3
```

`capstone` provides an alternative to the `gdb` disassembler, which could be useful specifically when dealing with complex/uncommon instructions.

`keystone` allows to generate opcodes, which can, for example, then be used as part of a shellcode.
![gef-shellcoder](https://i.imgur.com/BPdtr2D.png)

### Unicorn
[`unicorn`](https://github.com/unicorn-engine/unicorn) (also written by [Nguyen Anh Quynh](https://github.com/aquynh)) is a lightweight Qemu-based framework to emulate any architecture currently supported by `GDB` (and even some more).
Install is simple through the [released packages](https://github.com/unicorn-engine/unicorn/releases) but I would recommend instead to rely on the GIT master branch.
```bash
$ git clone https://github.com/unicorn-engine/unicorn.git && cd unicorn && ./make.sh && sudo ./make.sh install
```

`unicorn` integration in `gef` allows to emulate the behaviour to specific instructions (or block of instructions) based on the runtime context, without actually running it, and therefore sparing the trouble of saving the context/running the new context/restoring the old context. Additionally, `gef` can generate a standalone `unicorn` Python script, if you want/need to reproduce steps outside the debugger.


### ROPGadget
[`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) (written by [Jonathan Salwan](https://github.com/JonathanSalwan)) is simply the best cross-platform ROP gadget finder. It has been totally integrated inside `gef` to benefit of all of its awesomeness.
```bash
$ pip[23] install ropgadget
```

### Ropper
[`Ropper`](https://github.com/sashs/ropper) (written by [Sascha Schirra](https://github.com/sashs)) is another gadget finder. It supports opening multiple files and provides an awesome search option to find accurate gadgets.
```bash
$ pip[23] install ropper
```

### One-liner

Some of the optional dependencies can be installed using Python package
installer, `pip`. Simply run this
```bash
$ pip install ropgadget ropper capstone
```

## But why not PEDA?
Yes ! Why not ?! [PEDA](https://github.com/longld/peda) is a fantastic tool to
do the same, but is **only** to be used for x86-32 or x86-64. On the other hand,
`GEF` supports all the architecture supported by `GDB` (x86, ARM, MIPS, PowerPC,
SPARC, and so on).



## Bugs & Feedbacks

Go [here](https://github.com/hugsy/gef/issues)

## Contributors

`gef` was created and maintained by myself, `@_hugsy_`.
I would like to thank all the contributors to this project, including:

   * the people who committed some code (https://github.com/hugsy/gef/graphs/contributors)
   * and others:
      * @rick2600

## Happy hacking
