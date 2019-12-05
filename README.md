
![gef-context](https://heapme.f2tc.com/img/heapme-gdb-console.png)

## About this fork ##

`GEF` script and heap-analysis-helper patches to integrate with `HeapME` _(Heap Made Easy)_: https://heapme.f2tc.com/

* malloc/calloc/realloc/free updates the HeapME events array.
* One thread is dedicated to uploading events in groups to improve speed and reduce network overhead.
* Local HTTP Log Server will receive logs sent form your exploit script, and it will add these logs to the event queue to be uploaded in the correct order.

## How to use ##
1. Register and Login to https://heapme.f2tc.com/
2. Create a HeapME URL + Key
3. Load the heapme.py GEF script: \
`gef➤  source gef/scripts/heapme.py`
4. Execute `heapme init https://heapme.f2tc.com/<id> <key>` after `heap-analysis-helper`
5. Access and share the read-only page: `https://heapme.f2tc.com/<id>`

### Sample HeapME URL ###

[shellphish / how2heap / first_fit.c](https://github.com/shellphish/how2heap/blob/master/first_fit.c) demonstrating glibc malloc's first-fit behavior:

https://heapme.f2tc.com/wzqkgs5KNBX0ZZQ3moay

### HeapME Commands ###
* __heapme init &lt;id&gt; &lt;key&gt;__: Connect to the HeapMe URL and begins tracking dynamic heap allocation.
* __heapme watch &lt;address&gt;__: Updates the heap layout when this breakpoint is hit.
* __heapme push__: Uploads all events to the HeapME URL on-demand.

### TODO ###

* Interactive two-way communication between `HeapME` and `GEF`
* Create a standard way of (un)hooking to the different `GEF` heap-analysis-helper functions
* Create a GEF setting that will allow heap-analysis-helper commands to return an object besides using gef_print

# GDB Enhanced Features (a.k.a. GEF)

<p align="center">
  <img src="https://i.imgur.com/v3PUqPx.png" alt="logo"/>
</p>

`GEF` (pronounced ʤɛf - "Jeff") is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis and exploit development. Application developers will also benefit from it, as GEF lifts a great part of regular GDB obscurity, avoiding repeating traditional commands, or bringing out the relevant information from the debugging runtime.

## Instant Setup ##

Simply make sure you have [GDB 7.7 or higher](https://www.gnu.org/s/gdb) compiled with Python2 or Python3 bindings, then:

```bash
# via the install script
$ wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh

# manually
$ wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

Then just start playing:

```bash
$ gdb -q /path/to/my/bin
gef➤  gef help
```


## Highlights ##

A few of `GEF` features include:

  * **One** single GDB script.
  * Entirely **OS Agnostic**, **NO** dependencies: `GEF` is battery-included and is installable in 2 seconds (unlike [PwnDBG](https://github.com/pwndbg/pwndbg)).
  * **Fast** limiting the number of dependencies and optimizing code to make the
    commands as fast as possible (unlike _PwnDBG_).
  * Provides a great variety of commands to drastically change your experience in     GDB.
  * **Easily** extendable to create other commands by providing more comprehensible
    layout to GDB Python API.
  * Works consistently on both Python2 and Python3.
  * Built around an architecture abstraction layer, so all commands work in any
    GDB-supported architecture such as x86-32/64, ARMv5/6/7, AARCH64, SPARC, MIPS,
    PowerPC, etc. (unlike [PEDA](https://github.com/longld/peda))
  * Suited for real-life apps debugging, exploit development, just as much as
    CTF (unlike _PEDA_ or _PwnDBG_)

Check out the [Screenshot page](docs/screenshots.md) for more.


## Documentation ##

Unlike other GDB plugins, GEF has an extensive and up-to-date [documentation](https://gef.readthedocs.io/). Users are recommended to refer to it as it may help them in their attempts to use GEF. In particular, new users should navigate through it (see the [FAQ](https://gef.readthedocs.io/en/master/faq/) for common installation problems), and the problem persists, try to reach out for help on the IRC channel or submit an issue.


## Current status ##

| Documentation | License | Compatibility | IRC | Test validation |
|--|--|--|--|--|
| [![ReadTheDocs](https://readthedocs.org/projects/gef/badge/?version=master)](https://gef.readthedocs.org/en/master/) |  [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/hugsy/gef/blob/master/LICENSE) | [![Python 2 & 3](https://img.shields.io/badge/Python-2%20%26%203-green.svg)](https://github.com/hugsy/gef/) | [![IRC](https://img.shields.io/badge/freenode-%23%23gef-yellowgreen.svg)](https://webchat.freenode.net/?channels=##gef) | [![CircleCI status](https://circleci.com/gh/hugsy/gef/tree/master.svg?style=shield)](https://circleci.com/gh/hugsy/gef/tree/master) |



## Contribute ##

To get involved, refer to the [Contribution documentation](https://gef.readthedocs.io/en/master/#contribution) and the [guidelines](https://github.com/hugsy/gef/blob/dev/.github/CONTRIBUTING.md) to start.

And special thanks to [Pedro "TheZakMan" Araujo](https://thezakman.tumblr.com/) for the logo!.


## Happy Hacking ##
