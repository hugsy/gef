## Install GEF

There is **NO mandatory dependency** to have `gef` running contrarily to other projects.
A simple recent GDB compiled with Python scripting support will do.


### Pre-requisites

Only [GDB 7.7 and higher](https://www.gnu.org/s/gdb) is required. It must be
compiled with Python 3 support.

As of January 2020, GEF doesn't officially support Python 2 any longer, due to
Python 2 becoming officially deprecated.

This version of GEF will then only work for Python 3. If you absolutely require
GDB + Python 2, please use [GEF-Legacy](https://github.com/hugsy/gef-legacy)
instead. Note that `gef-legacy` won't provide new features, and only functional
bugs will be handled.

You can verify it with the following command:

```bash
$ gdb -nx -ex 'pi print(sys.version)' -ex quit
```

This should display your version of Python compiled with `gdb`.

```bash
$ gdb -nx -ex 'pi print(sys.version)' -ex quit
3.6.9 (default, Nov  7 2019, 10:44:02)
[GCC 8.3.0]
```

If you see an error here, it means that your GDB installation does not support Python.


### Setup from repository

The best way to use `GEF` is through cloning the git repository from GitHub, and
then sourcing the file from your `~/.gdbinit`.

```bash
$ git clone https://github.com/hugsy/gef.git  # or git pull to update
$ echo 'source /path/to/gef.py' >> ~/.gdbinit
```

### One-time setup script

If you only need `GEF` for a one-time environment (VMs, etc.) that do not
have/need `git` installed, just go with:

```bash
$ curl -s -L https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
```

### Optional dependencies

A few commands were added to `GEF` to extend its capabilities. It is
highly recommended to install the following modules (but not required):

- [`capstone`](https://github.com/aquynh/capstone) - disassembly engine
- [`Ropper`](https://github.com/sashs/Ropper) - an improved version of [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget)
- [`unicorn`](https://github.com/unicorn-engine/unicorn) - emulation engine
- [`keystone`](https://github.com/keystone-engine/keystone) - assembly engine

Some of those modules can be installed through `python-pip`. The following
commands will work for most distributions, but substitute `pip3` for versions of `gdb` compiled with Python 3:
```bash
$ pip install capstone
$ pip install ropper
```

Please refer to each project for installation and troubleshooting guides. As
`gef` works out of the box, please do not send issues to this project if you
have problems while installing those modules.

`gef` will assume the module installations are valid. Otherwise, it will
automatically disable all the `gef` commands that require this invalid module.


### Check setup

To check that `GEF` has been correctly installed, simply start a new `gdb`
session against any binary.
```bash
$ gdb -q /bin/ls
```

You should see the following header and prompt
```bash
$ gdb -q /bin/ls
gef loaded, `gef help' to start, `gef config' to configure
37 commands loaded (15 sub-commands), using Python engine 3.5
Reading symbols from /bin/ls...(no debugging symbols found)...done.
gef➤
```
