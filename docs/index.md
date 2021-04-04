# GEF - GDB Enhanced Features #

[![ReadTheDocs](https://readthedocs.org/projects/gef/badge/?version=master)](https://gef.readthedocs.org/en/master/) [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/master/LICENSE) [![Python 3](https://img.shields.io/badge/Python-3-green.svg)](https://github.com/hugsy/gef/) [![Discord](https://img.shields.io/badge/Discord-GDB--GEF-yellow)](https://discord.gg/HCS8Hg7)

`GEF` (pronounced ʤɛf - "Jeff") is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC to make GDB cool again for exploit dev. It is aimed to be used mostly by exploit developers and reverse-engineers, to provide additional features to GDB using the Python API to assist during the process of dynamic analysis and exploit development.

It has full support for both Python2 and Python3 indifferently (as more and more
distros start pushing `gdb` compiled with Python3 support).

![gef-context](https://i.imgur.com/E3EuQPs.png)

A few of `GEF` features include:

  * **One** single GDB script
  * Entirely **OS Agnostic**, **NO** dependencies: `GEF` is battery-included and [is installable instantly](https://gef.readthedocs.io/en/master/#setup)
  * **Fast** limiting the number of dependencies and optimizing code to make the commands as fast as possible
  * Provides [a great variety of commands](https://gef.readthedocs.io/en/master/commands/) to drastically change your experience in GDB.
  * [**Easily** extensible](https://gef.readthedocs.io/en/master/api/) to create other commands by providing more comprehensible layout to GDB Python API.
  * Full Python3 support ([Python2 support was dropped](https://github.com/hugsy/gef/releases/tag/2020.03) - see [`gef-legacy`](https://github.com/hugsy/gef-legacy)).
  * Built around an architecture abstraction layer, so all commands work in any GDB-supported architecture such as x86-32/64, ARMv5/6/7, AARCH64, SPARC, MIPS, PowerPC, etc.
  * Suited for real-life apps debugging, exploit development, just as much as CTF

Check out the [Screenshot page](https://gef.readthedocs.io/en/master/screenshots/) for more.

Or [try it online](https://demo.gef.blah.cat) (user:`gef`/password:`gef-demo`)


## Setup ##

### Quick install ###

Simply make sure you have [GDB 7.7 or higher](https://www.gnu.org/s/gdb).

```bash
# via the install script
$ wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh

# manually
$ wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```


Alternatively from inside `gdb` directly:

```bash
$ gdb -q
(gdb) pi \
import urllib.request as u, tempfile as t; \
g=t.NamedTemporaryFile(suffix='-gef.py'); \
open(g.name, 'wb+').write( u.urlopen('https://github.com/hugsy/gef/raw/master/gef.py').read() ); \
gdb.execute('source %s' % g.name)
```

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
# for Python2.x
$ pip2 install capstone unicorn keystone-engine ropper

# for Python3.x
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
$ wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef-extras.sh | sh

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

Or if you just like the tool, feel free to drop a simple *"thanks"* on Discord, Twitter or other, it is **always** very appreciated.



## Open-Source Rewards ##

I love Open-Source, and just like my [other projects](https://proxenet.readthedocs.io/en/latest/#contributing) I've decided to offer a :beer: 4 :bug: (a.k.a *beer4bugs*) bounty for `GEF`, to thank everybody who helps keeping the project living and always better.

The rule is simple, provide a (substantial) contribution to `GEF`, such as:

   1. Submitting a Pull-Request for a new feature/command.
   2. Submitting a Pull-Request for a new architecture support.
   3. Or sending a relevant issue request (like a bug, crash, or else).

Come on our [Discord channel](https://discord.gg/HCS8Hg7) to talk about it, and next time we meet in person (like at a conference), I'll be happy to pay you a beer.

I do also accept beers if you think that the tool is cool! :wink:

Cheers :beers:

### Happy hacking ###
