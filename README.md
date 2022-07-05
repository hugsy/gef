<p align="center">
  <img src="https://i.imgur.com/o0L8lPN.png" alt="logo"/>
</p>

<p align="center">
    <a href="https://discord.gg/HCS8Hg7"><img alt="Discord" src="https://img.shields.io/badge/Discord-BlahCats-yellow"></a>
  <a href="https://hugsy.github.io/gef"><img alt="Docs" src="https://img.shields.io/badge/Docs-gh--pages-brightgreen"></a>
  <a title="Use the IDs: gef/gef-demo" href="https://demo.gef.blah.cat"><img alt="Try GEF" src="https://img.shields.io/badge/Demo-Try%20GEF%20Live-blue"></a>
</p>

`GEF` (pronounced ʤɛf - "Jeff") is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis and exploit development. Application developers will also benefit from it, as GEF lifts a great part of regular GDB obscurity, avoiding repeating traditional commands, or bringing out the relevant information from the debugging runtime.



## Instant Setup ##

Simply make sure you have [GDB 8.0 or higher](https://www.gnu.org/s/gdb) compiled with Python3.6+ bindings, then:


```bash
# via the install script
## using curl
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

## using wget
$ bash -c "$(wget https://gef.blah.cat/sh -O -)"

# or manually
$ wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# or alternatively from inside gdb directly
$ gdb -q
(gdb) pi import urllib.request as u, tempfile as t; g=t.NamedTemporaryFile(suffix='-gef.py'); open(g.name, 'wb+').write(u.urlopen('https://tinyurl.com/gef-main').read()); gdb.execute('source %s' % g.name)
```

_Note_: to fetch the latest of GEF (i.e. from the `dev` branch), simply replace in the URL to https://gef.blah.cat/dev.

You can immediately see that GEF is correctly installed by launching GDB:

![gef-context](https://i.imgur.com/E3EuQPs.png)

A few of `GEF` features include:

  * **One** single GDB script
  * Entirely **OS Agnostic**, **NO** dependencies: `GEF` is battery-included and [is installable instantly](https://hugsy.github.io/gef/#setup)
  * **Fast** limiting the number of dependencies and optimizing code to make the commands as fast as possible
  * Provides a great variety of commands to drastically change your experience in GDB.
  * [**Easily** extensible](https://hugsy.github.io/gef/api/) to create other commands by providing more comprehensible layout to GDB Python API.
  * Full Python3 support ([Python2 support was dropped](https://github.com/hugsy/gef/releases/tag/2020.03) - see [`gef-legacy`](https://github.com/hugsy/gef-legacy)).
  * Built around an architecture abstraction layer, so all commands work in any GDB-supported architecture such as x86-32/64, ARMv5/6/7, AARCH64, SPARC, MIPS, PowerPC, etc.
  * Suited for real-life apps debugging, exploit development, just as much as CTF

Check out the [Screenshot page](docs/screenshots.md) for more or [try it online](https://demo.gef.blah.cat) (user:`gef`/password:`gef-demo`)


## Documentation ##

Unlike other GDB plugins, GEF has an extensive and up-to-date [documentation](https://hugsy.github.io/gef/). Users are recommended to refer to it as it may help them in their attempts to use GEF. In particular, new users should navigate through it (see the [FAQ](https://hugsy.github.io/gef/faq/) for common installation problems), and the problem persists, try to reach out for help on the Discord channel or submit an issue.


## Current status ##

| Documentation |License | Compatibility | CI Tests (`main`) | CI Tests (`dev`) |
|:---:|:---:|:---|--|--|
| [![Documentation](https://github.com/hugsy/gef/actions/workflows/generate-docs.yml/badge.svg)](https://github.com/hugsy/gef/actions/workflows/generate-docs.yml) | [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/main/LICENSE) | [![Python 3](https://img.shields.io/badge/Python-3-green.svg)](https://github.com/hugsy/gef/) | [![CI Test for GEF](https://github.com/hugsy/gef/actions/workflows/run-tests.yml/badge.svg)](https://github.com/hugsy/gef/actions/workflows/run-tests.yml) | [![CI Test for GEF](https://github.com/hugsy/gef/actions/workflows/run-tests.yml/badge.svg?branch=dev)](https://github.com/hugsy/gef/actions/workflows/run-tests.yml) |


## Contribute ##

To get involved, refer to the [Contribution documentation](https://hugsy.github.io/gef/#contribution) and the [guidelines](https://github.com/hugsy/gef/blob/dev/.github/CONTRIBUTING.md) to start.

## Sponsors ##

Another way to contribute to keeping the project alive is by sponsoring it! Check out [the sponsoring documentation](https://hugsy.github.io/gef/#sponsors) for details so you can be part of the list of those [awesome sponsors](https://github.com/sponsors/hugsy).


## Happy Hacking 🍻 ##
