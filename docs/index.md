# GEF - GDB Enhanced Features #

[![ReadTheDocs](https://readthedocs.org/projects/gef/badge/?version=master)](https://gef.readthedocs.org/en/master/) [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/master/LICENSE) [![Python 3](https://img.shields.io/badge/Python-3-green.svg)](https://github.com/hugsy/gef/) [![Discord](https://img.shields.io/badge/Discord-GDB--GEF-yellow)](https://discord.gg/HCS8Hg7)

`GEF` (pronounced ʤɛf - "Jeff") is a kick-ass set of commands for X86, ARM,
MIPS, PowerPC and SPARC to make GDB cool again for exploit dev. It is aimed to
be used mostly by exploit developers and reverse-engineers, to provide
additional features to GDB using the Python API to assist during the process of
dynamic analysis and exploit development.

It has full support for both Python2 and Python3 indifferently (as more and more
distros start pushing `gdb` compiled with Python3 support).

![gef-context](https://i.imgur.com/E3EuQPs.png)

A few of `GEF` features include:

  * **One** single GDB script
  * Entirely **OS Agnostic**, **NO** dependencies: `GEF` is battery-included
    and [is installable instantly](https://gef.readthedocs.io/en/master/#setup)
  * **Fast** limiting the number of dependencies and optimizing code to make
    the commands as fast as possible
  * Provides [a great variety of
    commands](https://gef.readthedocs.io/en/master/commands/) to drastically
    change your experience in GDB.
  * [**Easily** extensible](https://gef.readthedocs.io/en/master/api/) to
    create other commands by providing more comprehensible layout to GDB Python
    API.
  * Full Python3 support ([Python2 support was
    dropped](https://github.com/hugsy/gef/releases/tag/2020.03) - see
    [`gef-legacy`](https://github.com/hugsy/gef-legacy)).
  * Built around an architecture abstraction layer, so all commands work in any
    GDB-supported architecture such as x86-32/64, ARMv5/6/7, AARCH64, SPARC,
    MIPS, PowerPC, etc.
  * Suited for real-life debugging, exploit development, just as much as for
    CTFs

Check out the [Screenshot
page](https://gef.readthedocs.io/en/master/screenshots/) for more.

Or [try it online](https://demo.gef.blah.cat) (user:`gef`/password:`gef-demo`)


## Setup ##

### Quick install ###

Simply make sure you have [GDB 8.0 or higher](https://www.gnu.org/s/gdb), compiled with Python 3.6 or higher.

```bash
$ bash -c "$(curl -fsSL http://gef.blah.cat/sh)"
```

For more details and other ways to install GEF please see [./config.md](the
config docs).

### Run ###

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

If your host/VM is connected to the Internet, you can update `gef` easily to the
latest version (even without `git` installed). with
`python /path/to/gef.py --update`

```bash
$ python ~/.gdbinit-gef.py --update
Updated
```

This will deploy the latest version of `gef`'s _master_ branch from Github.
If no updates are available, `gef` will respond `No update` instead.


### Install via Git ###

To install from Git, simply clone this repository and specify the path to
`gef.py` inside the `~/.gdbinit` file:

```bash
$ git clone https://github.com/hugsy/gef.git
$ echo source `pwd`/gef/gef.py >> ~/.gdbinit
```

If you like living on the edge, you can then switch to the `dev` branch:

```bash
$ git checkout dev
```


## Dependencies ##

There are **none**: `GEF` works out of the box!

However, to enjoy all the coolest features from some commands, it is recommended
to install:

- [`capstone`](https://github.com/aquynh/capstone)
- [`keystone`](https://github.com/keystone-engine/keystone)
- [`unicorn`](https://github.com/unicorn-engine/unicorn)
- [`Ropper`](https://github.com/sashs/ropper)


For a quick installation, simply use the `pip` packaged version:

```bash
$ pip3 install capstone unicorn keystone-engine ropper
```

Just make sure you are using the `pip` corresponding to the version of Python
your GDB was compiled with. If you are experiencing issues installing them,
post an issue on the GitHub of the respective projects. If your bug is not
related to `GEF`, you will not get an answer.


## Additional commands ##

GEF was built to also provide a solid base for external scripts. The
repository [`gef-extras`](https://github.com/hugsy/gef-extras) is an open
repository where anyone can freely submit their own commands to extend GDB via
GEF's API.

To benefit from it:
```bash
# via the install script
$ bash -c "$(wget https://github.com/hugsy/gef/raw/master/scripts/gef-extras.sh -O -)"

# manually
# clone the repo
$ https://github.com/hugsy/gef-extras.git
# specify gef to load this directory
$ gdb -ex 'gef config gef.extra_plugins_dir "/path/to/gef-extras/scripts"' -ex 'gef save' -ex quit
[+] Configuration saved
```

You can also use the structures defined from this repository:
```bash
$ gdb -ex 'gef config pcustom.struct_path "/path/to/gef-extras/structs"' -ex 'gef save' -ex quit
[+] Configuration saved
```

There, you're now fully equipped epic pwnage with **all** GEF's goodness!!


## Bugs & Feedbacks ##

To discuss `gef`, `gdb`, exploitation or other topics, feel free to join our [Discord channel](https://discord.gg/HCS8Hg7).

For bugs or feature requests, just go [here](https://github.com/hugsy/gef/issues) and provide a thorough description if you want help.

_Side Note_: `GEF` fully relies on the GDB API and other Linux-specific sources of information (such as `/proc/<pid>`). As a consequence, some of the features might not work on custom or hardened systems such as GrSec.

## Contribution ##

`gef` was created and maintained by myself, [`@_hugsy_`](https://twitter.com/_hugsy_), but kept fresh thanks to [all the contributors](https://github.com/hugsy/gef/graphs/contributors).

[ ![contributors-img](https://contrib.rocks/image?repo=hugsy/gef) ](https://github.com/hugsy/gef/graphs/contributors)

Or if you just like the tool, feel free to drop a simple *"thanks"* on Discord, Twitter or other, it is **always** very appreciated.

## Sponsors ##

We would like to thank in particular the following people who've been sponsoring GEF allowing us to dedicate more time and resources to the project:

[<img src="https://github.com/nkaretnikov.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/nkaretnikov)
[<img src="https://github.com/R3zk0n.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/r3zk0n)
[<img src="https://github.com/merces.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/merces)
[<img src="https://github.com/nbars.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/nbars)
[<img src="https://github.com/maycon.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/maycon)
[<img src="https://github.com/jespinhara.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/jespinhara)
[<img src="https://github.com/therealdreg.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/therealdreg)
[<img src="https://github.com/mikesart.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/mikesart)


### Extra Credits ###

 - The GEF logo was designed by [TheZakMan](https://twitter.com/thezakman)


### Happy hacking ###
