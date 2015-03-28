# GEF - GDB Enhanced Features

`GEF` is aimed to be used mostly by exploiters and reverse-engineers. It
provides additional features to GDB using the Python API to assist during the
process of dynamic analysis or exploit development.

`GEF` fully relies on GDB API and other Linux specific source of information
(such as `/proc/pid`). As a consequence, some of the features might not work on
custom or harden systems such as GrSec.
It has fully support for Python2 and Python3 indifferently (as more and more
distro start pushing `gdb` compiled with Python3 support).


## But why not PEDA?
Yes ! Why not ?! [PEDA](https://github.com/longld/peda) is a fantastic tool to
do the same, but is **only** to be used for x86-32 or x86-64. On the other hand,
GEF supports all the architecture supported by `GDB` (x86, ARM, MIPS, PowerPC,
SPARC, and so on).
I love `PEDA` and use it litterally all the time whenever I'm facing a Intel
binary. And so should you. But being Intel only prevents from having fun with
other architectures.


## Show me

### x86
![gef-x86](https://pbs.twimg.com/media/BvdRAJKIUAA8R6_.png:large)

### ARM
![gef-arm](https://pbs.twimg.com/media/CA_y-xEU0AAroF3.png:large)

### PowerPC
![gef-ppc](https://i.imgur.com/IN6x6lw.png)

### Mips64
![gef-mips](https://i.imgur.com/WTXutso.png)


## Enough, I wanna try it

Simply make sure you're having a [GDB 7+](https://www.gnu.org/s/gdb).
``` bash
$ git clone https://github.com/hugsy/gef.git
$ echo source /path/to/dir/gef.py > ~/.gdbinit
$ gdb -q /path/to/my/bin
```

Then just start playing:
```bash
gef> gef help
```

## Dependencies

`GEF` works out of the box. However, to enjoy all the coolest features, it is
recommended to install:

- [capstone](https://github.com/aquynh/capstone) **highly** recommended
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) **highly** recommended
- [python-radare2](https://github.com/radare/radare2-bindings)

*Note*: if you are using GDB with Python3 support, you cannot use `ROPgadget` as
 Python3 support has not implemented yet. `Capstone` and `radare2-python` will
 work just fine.

*Another note*: `Capstone` is packaged for Python 2 and 3 with `pip`. So a quick install is 
```bash 
$ pip2 install capstone    # for Python2.x
$ pip3 install capstone    # for Python3.x
```


## Bugs & Feedbacks

Go [here](https://github.com/hugsy/gef/issues)

### Happy hacking
