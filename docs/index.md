# GEF - GDB Enhanced Features

[![Docs](https://img.shields.io/badge/Documentation-blue.svg)](https://hugsy.github.io/gef/) [![Coverage](https://img.shields.io/badge/Coverage-purple.svg)](https://hugsy.github.io/gef/coverage/) [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/main/LICENSE) [![Python 3](https://img.shields.io/badge/Python-3-green.svg)](https://github.com/hugsy/gef/) [![Discord](https://img.shields.io/badge/Discord-GDB--GEF-yellow)](https://discord.gg/HCS8Hg7)

`GEF` (pronounced ʤɛf - "Jeff") is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC
to make GDB cool again for exploit dev. It is aimed to be used mostly by exploit developers and
reverse-engineers, to provide additional features to GDB using the Python API to assist during the
process of dynamic analysis and exploit development.

It requires Python 3, but [`gef-legacy`](https://github.com/hugsy/gef-legacy) can be used if Python
2 support is needed.

![gef-context](https://i.imgur.com/E3EuQPs.png)

## GDB Made Easy

* **One** single GDB script
* Entirely **architecture agnostic**, **NO** dependencies: `GEF` is battery-included and [is
  installable instantly](https://hugsy.github.io/gef/#setup)
* **Fast** limiting the number of dependencies and optimizing code to make the commands as fast as
  possible
* Provides a great variety of commands to drastically change your debugging experience in GDB.
* [**Easily** extensible](https://hugsy.github.io/gef/api/) to create other commands by providing
  more comprehensible layout to GDB Python API.
* Full Python3 support ([Python2 support was dropped in
  2020.03](https://github.com/hugsy/gef/releases/tag/2020.03)) - check out
  [`gef-legacy`](https://github.com/hugsy/gef-legacy) for a Python2 compatible version, and [the
  compatibility matrix](/docs/compat.md) for a complete rundown of version support.
* Built around an architecture abstraction layer, so all commands work in any GDB-supported
  architecture such as x86-32/64, ARMv5/6/7, AARCH64, SPARC, MIPS, PowerPC, etc.
* Suited for real-life debugging, exploit development, just as much as for CTFs
* And a lot more commands contributed by the community available on
[GEF-Extras](https://github.com/hugsy/gef-extras) !!

Check out the [showroom page](https://hugsy.github.io/gef/screenshots/) for more | or [try it online
yourself!](https://demo.gef.blah.cat) (user:`gef`/password:`gef-demo`)

## Quick start

### Automated installation

GEF has no dependencies, is fully battery-included and works out of the box. You can get started
with GEF in a matter of seconds, by simply running:

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

For more details and other ways to install GEF please see [installation
page](https://hugsy.github.io/gef/install/).

### Run

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

## Bugs & Feedbacks

To discuss `gef`, `gdb`, exploitation or other topics, feel free to join our [Discord
channel](https://discord.gg/HCS8Hg7).

For bugs or feature requests, just go [here](https://github.com/hugsy/gef/issues) and provide a
thorough description if you want help.

_Side Note_: `GEF` fully relies on the GDB API and other Linux-specific sources of information (such
as `/proc/<pid>`). As a consequence, some of the features might not work on custom or hardened
systems such as GrSec.

## Contribution

`gef` was created and maintained by myself, [`@_hugsy_`](https://twitter.com/_hugsy_), but kept
fresh thanks to [all the contributors](https://github.com/hugsy/gef/graphs/contributors).

[![contributors-img](https://contrib.rocks/image?repo=hugsy/gef)](https://github.com/hugsy/gef/graphs/contributors)

Or if you just like the tool, feel free to drop a simple _"thanks"_ on Discord, Twitter or other, it
is **always** very appreciated.

## Sponsors

We would like to thank in particular the following people who've been sponsoring GEF allowing us to
dedicate more time and resources to the project:

[<img src="https://github.com/nkaretnikov.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/nkaretnikov)
[<img src="https://github.com/R3zk0n.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/r3zk0n)
[<img src="https://github.com/merces.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/merces)
[<img src="https://github.com/nbars.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/nbars)
[<img src="https://github.com/maycon.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/maycon)
[<img src="https://github.com/jespinhara.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/jespinhara)
[<img src="https://github.com/therealdreg.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/therealdreg)
[<img src="https://github.com/mikesart.png" height="50px" width="50px" style="border-radius: 50%">](https://github.com/mikesart)

## Extra Credits

* The GEF logo was designed by [TheZakMan](https://twitter.com/thezakman)

## 🍺 Happy hacking
