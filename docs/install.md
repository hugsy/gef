## Installing GEF

## Prerequisites

Specific GEF commands rely on commonly used Unix commands to extract additional information.
Therefore it requires the following binaries to be present:

*  `file`
*  `readelf`
*  `ps`
*  `python3`

Those tools are included by default in many modern distributions. If they're missing, you can use
your OS package manager to install them.

### GDB

Only [GDB 8 and higher](https://www.gnu.org/s/gdb) is required. It must be compiled with Python 3.6
or higher support. For most people, simply using your distribution package manager should be enough.

As of January 2020, GEF officially doesn't support Python 2 any longer, due to Python 2 becoming
officially deprecated.

GEF will then only work for Python 3. If you absolutely require GDB + Python 2, please use
[GEF-Legacy](https://github.com/hugsy/gef-legacy) instead. Note that `gef-legacy` won't provide new
features, and only functional bugs will be handled.

You can verify it with the following command:

```bash
gdb -nx -ex 'pi print(sys.version)' -ex quit
```

This should display your version of Python compiled with `gdb`.

```bash
$ gdb -nx -ex 'pi print(sys.version)' -ex quit
3.6.9 (default, Nov  7 2019, 10:44:02)
[GCC 8.3.0]
```

### Python dependencies

There are **none**: `GEF` works out of the box!

GEF itself provides most (if not all 🤯) features required for typical sessions. However, GEF can be
easily extended via

*  community-built scripts, functions and architectures in the repo
   `gef-extras` (see below)
*  your own script which can leverage the GEF API for the heavy lifting

## Standalone

### Quick install

The quickest way to get started with GEF is through the installation script available. Simply make
sure you have [GDB 8.0 or higher](https://www.gnu.org/s/gdb), compiled with Python 3.6 or higher,
and run

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Or if you prefer `wget`

```bash
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

Alternatively from inside `gdb` directly:

```bash
$ gdb -q
(gdb) pi import urllib.request as u, tempfile as t; g=t.NamedTemporaryFile(suffix='-gef.py'); open(g.name, 'wb+').write(u.urlopen('https://tinyurl.com/gef-main').read()); gdb.execute('source %s' % g.name)
```

That's it! GEF is installed and correctly set up. You can confirm it by checking the `~/.gdbinit`
file and see a line that sources (i.e. loads) GEF.

```bash
$ cat ~/.gdbinit
source ~/.gdbinit-gef.py
```

### Update

If your host/VM is connected to the Internet, you can update `gef` easily to the latest version
(even without `git` installed). with `python /path/to/gef.py --update`

```bash
$ python ~/.gdbinit-gef.py --update
Updated
```

This will deploy the latest version of `gef`'s _main_ branch from Github. If no
updates are available, `gef` will respond `No update` instead.

## Using git

To contribute to GEF, you might prefer using git directly.

```bash
git clone https://github.com/hugsy/gef.git
echo source `pwd`/gef/gef.py >> ~/.gdbinit
```


## Community repository: GEF-Extras

GEF was built to also provide a solid base for external scripts. The repository
[`gef-extras`](https://github.com/hugsy/gef-extras) is an open repository where
anyone can freely submit their own commands to extend GDB via GEF's API.

To benefit from it:

```bash
# using the automated way
## via the install script
$ bash -c "$(wget https://github.com/hugsy/gef/raw/main/scripts/gef-extras.sh -O -)"

# or manually
## clone the repo
$ git clone --branch main https://github.com/hugsy/gef-extras.git

## then specify gef to load this directory
$ gdb -ex 'gef config gef.extra_plugins_dir "/path/to/gef-extras/scripts"' -ex 'gef save' -ex quit
[+] Configuration saved
```

You can also use the structures defined from this repository:

```bash
$ gdb -ex 'gef config pcustom.struct_path "/path/to/gef-extras/structs"' -ex 'gef save' -ex quit
[+] Configuration saved
```

There, you're now fully equipped epic pwnage with **all** GEF's goodness!!

# Uninstalling GEF

## Prevent script loading

GDB provides the `-nx` command line flag to disable the commands from the
`~/.gdbinit` to be executed.

```text
gdb -nx
```

## Disable GEF

To disable GEF without removing it, go to editing `~/.gdbinit`, spot the line
that sources GEF, and comment / delete that line:

So:

```text
$ cat ~/.gdbinit
source /my/path/to/gef.py
```

Will become:

```text
$ cat ~/.gdbinit
# source /my/path/to/gef.py
```

Restart GDB, GEF is gone. Note that you can also load GEF at any moment during
your GDB session as such:

```text
$ gdb
(gdb) source /my/path/to/gef.py
```

## Remove GEF

GEF is a one-file GDB script. Therefore, to remove GEF simply spot the location
it was installed (for example, by using `~/.gdbinit`) and delete the file. If a
configuration file was created, it will be located as `~/.gef.rc` and can also
be deleted:

```text
$ cat ~/.gdbinit
# source /my/path/to/gef.py
$ rm /my/path/to/gef.py ~/.gef.rc
```

GEF is totally removed from your system.
