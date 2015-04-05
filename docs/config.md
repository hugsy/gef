## Install GEF

### Pre-requisites
Only [GDB 7.x+](https://www.gnu.org/s/gdb) is required. It must compiled with
Python 2 or 3 support. This can be verified with the following command:

``` bash
$ gdb -nx -ex 'python print (sys.version)' -ex quit
```

This should display your version of Python compiled with `gdb`.

For example, with Python2
```bash
$ gdb -nx -ex 'python print (sys.version)' -ex quit
2.7.3 (default, Mar 18 2014, 06:31:17)
[GCC 4.6.3]
```

Or Python3
```bash
$ gdb -nx -ex 'python print (sys.version)' -ex quit
3.4.0 (default, Apr 11 2014, 13:08:40)
[GCC 4.8.2]
```


### Setup from repository

The best way to use `GEF` is through cloning the git repository from GitHub, and
source the file from your `~/.gdbinit`.

``` bash
$ git clone https://github.com/hugsy/gef.git  # or git pull to update
$ echo 'source /path/to/gef.py' >> ~/.gdbinit
```

### One-time setup script

If you only need `GEF` for a one-time environment (VMs, etc.) that do not
have/need `git` installed, just go with:

``` bash
$ curl -s -L https://github.com/hugsy/gef/raw/master/gef.sh | sh
```

### Optional dependancies

A few commands were added to `GEF` to extend its possibilities. It is
recommended to install the following modules:

- [`capstone`](https://github.com/aquynh/capstone) **highly** recommended
- [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) **highly** recommended
- [`python-radare2`](https://github.com/radare/radare2-bindings)

It is recommended to install those modules through `python-pip`. The following
commands will work for most distributions.
```bash
$ pip install capstone
$ pip install ropgadget
```

`radare2-python` is not packaged through `python-pip`. However, many
distributions package `radare2` suite and its bindings. Last option will be to
set it up from the source (compilation and installation).


*Note*: GDB/Python3 users should be aware that `ROPgadget` does not supported
 (yet?) Python3.


### Check setup

To check that `GEF` has been correctly installed, simply start a new `gdb`
session against any binary.
```bash
$ gdb -q /bin/ls
```

You should see the following header and prompt
```bash
$ gdb-gef -q /bin/ls
gef loaded, `gef help' to start, `gef config' to configure
29 commands loaded (10 sub-commands), using Python engine 2.7
Reading symbols from /bin/ls...(no debugging symbols found)...done.
gef>
```

When loading, `gef` will check for dependencies. If it fails to load them, you
will see a warning like:
```bash
[+] Failed to load `assemble`: 'radare2 Python bindings could not be loaded'
```

This simply means that the associated commands will not be available. If you
want those commands, simply install the modules.
