# GEF - GDB Enhanced Features  [![Documentation Status](https://readthedocs.org/projects/gef/badge/?version=latest)](https://gef.readthedocs.org/en/latest/)

**TL;DR**: `GEF` is a kick-ass set commands for X86, ARM, MIPS, etc. to
make GDB cool again for exploit dev.

`GEF` is aimed to be used mostly by exploiters and reverse-engineers. It
provides additional features to GDB using the Python API to assist during the
process of dynamic analysis or exploit development.

`GEF` fully relies on GDB API and other Linux specific source of information
(such as `/proc/pid`). As a consequence, some of the features might not work on
custom or harden systems such as GrSec.
It has fully support for Python2 and Python3 indifferently (as more and more
distro start pushing `gdb` compiled with Python3 support).


## Quick start

Simply make sure you're having a [GDB 7.x+](https://www.gnu.org/s/gdb).
``` bash
 $ wget -q -O- https://github.com/hugsy/gef/raw/master/gef.sh | sh
```

Then just start playing (for local files):
```bash
$ gdb -q /path/to/my/bin
gef> gef help
```

Or (for remote debugging)
```bash
remote:~ $ gdbserver 0.0.0.0:1234 /path/to/file 
```
And 
```bash
local:~ $ gdb -q
gef> gef-remote your.ip.address:1234
```

## Show me

#### x86
![gef-x86](https://i.imgur.com/P6ZGp6E.png)

#### ARM
![gef-arm](http://i.imgur.com/qOL8CnL.png)

#### PowerPC
![gef-ppc](https://i.imgur.com/IN6x6lw.png)

#### MIPS
![gef-mips](https://i.imgur.com/dBaB9os.png)


## Dependencies

There are none: `GEF` works out of the box!
However, to enjoy all the coolest features, it is recommended to install:

- [`capstone`](https://github.com/aquynh/capstone) **highly** recommended
- [`keystone`](https://github.com/aquynh/keystone) **highly** recommended
- [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) **highly** recommended

*Note*: You can use `pip` to simply and quickly install the (optional) dependencies.
```bash
$ pip2 install capstone    # for Python2.x
$ pip3 install capstone    # for Python3.x
```

And same goes for `ropgadget`
```bash
$ pip[23] install ropgadget
```


## But why not PEDA?
Yes ! Why not ?! [PEDA](https://github.com/longld/peda) is a fantastic tool to
do the same, but is **only** to be used for x86-32 or x86-64. On the other hand,
`GEF` supports all the architecture supported by `GDB` (x86, ARM, MIPS, PowerPC,
SPARC, and so on).



## Bugs & Feedbacks

Go [here](https://github.com/hugsy/gef/issues)

### Happy hacking
