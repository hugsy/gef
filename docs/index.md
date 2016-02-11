# GEF - GDB Enhanced Features  [![Documentation Status](https://readthedocs.org/projects/gef/badge/?version=latest)](https://gef.readthedocs.org/en/latest/)

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
remote:~ $ gdbserver /path/to/my/remote/file 0.0.0.0:1234
```
And 
```bash
local:~ $ gdb -q
gef> gef-remote your.ip.address:1234
```

## Show me

### x86
![gef-x86](https://i.imgur.com/P6ZGp6E.png)

### ARM
![gef-arm](https://pbs.twimg.com/media/CA_y-xEU0AAroF3.png:large)

### PowerPC
![gef-ppc](https://i.imgur.com/IN6x6lw.png)

### Mips
![gef-mips](https://i.imgur.com/dBaB9os.png)


## Dependencies

There are none: `GEF` works out of the box!
However, to enjoy all the coolest features, it is recommended to install:

- [`capstone`](https://github.com/aquynh/capstone) **highly** recommended
- [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) **highly** recommended
- [`python-radare2`](https://github.com/radare/radare2-bindings)

*Note*: if you are using GDB with Python3 support, you cannot use `ROPgadget` as
 Python3 support has not implemented yet. `Capstone` and `radare2-python` will
 work just fine.

*Another note*: `Capstone` is packaged for Python 2 and 3 with `pip`. So a quick install is
```bash
$ pip2 install capstone    # for Python2.x
$ pip3 install capstone    # for Python3.x
```

And for `ropgadget`
```bash
$ pip install ropgadget
```

`python-radare2` is not packaged by `pip`, you might need to install it the old school way.


## But why not PEDA?
Yes ! Why not ?! [PEDA](https://github.com/longld/peda) is a fantastic tool to
do the same, but is **only** to be used for x86-32 or x86-64. On the other hand,
`GEF` supports all the architecture supported by `GDB` (x86, ARM, MIPS, PowerPC,
SPARC, and so on).
I love `PEDA` and use it litterally all the time whenever I'm facing a Intel
binary. And so should you. But being Intel only prevents from having fun with
other architectures.


## Bugs & Feedbacks

Go [here](https://github.com/hugsy/gef/issues)

### Happy hacking
