<p align="center">
  <img src="https://i.imgur.com/o0L8lPN.png" alt="logo"/>
</p>

`GEF` (pronounced ʤɛf - "Jeff") is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis and exploit development. Application developers will also benefit from it, as GEF lifts a great part of regular GDB obscurity, avoiding repeating traditional commands, or bringing out the relevant information from the debugging runtime.


## Instant Setup ##

Simply make sure you have [GDB 8.0 or higher](https://www.gnu.org/s/gdb) compiled with Python3.6+ bindings, then:


```bash
# via the install script
## using curl
$ bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

## using wget
$ bash -c "$(wget http://gef.blah.cat/sh -O -)"

# or manually
$ wget -O ~/.gdbinit-gef.py -q http://gef.blah.cat/py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# or alternatively from inside gdb directly
$ gdb -q
(gdb) pi import urllib.request as u, tempfile as t; g=t.NamedTemporaryFile(suffix='-gef.py'); open(g.name, 'wb+').write(u.urlopen('https://tinyurl.com/gef-master').read()); gdb.execute('source %s' % g.name)
```

_Note_: to fetch the latest of GEF (i.e. from the `dev` branch), simply replace in the URL to http://gef.blah.cat/dev.

You can immediately see that GEF is correctly installed by launching GDB:

```bash
$ gdb -q /path/to/my/bin
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 9.1 using Python engine 3.8
gef➤  gef help
```

_Note_: As of January 2020, GEF doesn't officially support Python 2 any longer, due to Python 2 becoming officially deprecated.
If you really need GDB+Python2, use the (not actively maintained) [`gef-legacy`](https://github.com/hugsy/gef-legacy) instead.


## Community ##

[![Discord](https://img.shields.io/badge/Discord-GDB--GEF-yellow)](https://discord.gg/HCS8Hg7)

_Note_: For maintenance simplicity, the unified communities on IRC/Gitter/Slack/Discord based [MatterBridge](https://github.com/42wim/matterbridge) are now discontinued. The GEF Discord is now the only way for talking with us!

## Highlights ##

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

Check out the [Screenshot page](docs/screenshots.md) for more.

Or [try it online](https://demo.gef.blah.cat) (user:`gef`/password:`gef-demo`)


## Documentation ##

Unlike other GDB plugins, GEF has an extensive and up-to-date [documentation](https://gef.readthedocs.io/). Users are recommended to refer to it as it may help them in their attempts to use GEF. In particular, new users should navigate through it (see the [FAQ](https://gef.readthedocs.io/en/master/faq/) for common installation problems), and the problem persists, try to reach out for help on the Discord channel or submit an issue.


## Current status ##


| Documentation |License | Compatibility |
|:---:|:---:|:---|
| [![ReadTheDocs](https://readthedocs.org/projects/gef/badge/?version=master)](https://gef.readthedocs.org/en/master/) | [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/master/LICENSE) | [![Python 3](https://img.shields.io/badge/Python-3-green.svg)](https://github.com/hugsy/gef/) |


## Contribute ##

To get involved, refer to the [Contribution documentation](https://gef.readthedocs.io/en/master/#contribution) and the [guidelines](https://github.com/hugsy/gef/blob/dev/.github/CONTRIBUTING.md) to start.

## Sponsors ##

Another way to contribute to keeping the project alive is by sponsoring it! Check out [the sponsoring documentation](https://gef.readthedocs.io/en/master/#sponsors) for details so you can be part of the list of those [awesome sponsors](https://github.com/sponsors/hugsy).


## Happy Hacking   ##
