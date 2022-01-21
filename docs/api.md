# Extending GEF

`GEF` intends to provide a battery-included, quickly installable and crazy fast
debugging environment sitting on top of GDB.

But it most importantly provides all the primitives required to allow hackers to
quickly create their own commands. This page intends to summarize how to
create advanced GDB commands in moments using `GEF` as a library.

A [dedicated repository](https://github.com/hugsy/gef-extras) was born to host
[external scripts](https://github.com/hugsy/gef-extras/tree/master/scripts). This
repo is open to all for contributions, no restrictions and the most valuable
ones will be integrated into `gef.py`.

## Quick start

Here is the most basic skeleton for creating a new `GEF` command named `newcmd`:

```python
class NewCommand(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "newcmd"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # let's say we want to print some info about the architecture of the current binary
        print(f"gef.arch={gef.arch}")
        # or showing the current $pc
        print(f"gef.arch.pc={gef.arch.pc:#x}")
        return

register_external_command(NewCommand())
```

Loading it in `GEF` is as easy as
```
gef➤  source /path/to/newcmd.py
[+] Loading 'NewCommand'
```

We can call it:

```
gef➤  newcmd
gef.arch=<__main__.X86_64 object at 0x7fd5583571c0>
gef.arch.pc=0x55555555a7d0
```

Yes, that's it! Check out [the complete API](api/gef.md) to see what else GEF offers.

## Detailed explanation

Our new command must be a class that inherits from GEF's `GenericCommand`. The
*only* requirements are:

 * a `_cmdline_` attribute (the command to type on the GDB prompt).
 * a `_syntax_` attribute, which GEF will use to auto-generate the help menu.
 * a method `do_invoke(self, args)` which will be executed when the command
   is invoked. `args` is a list of the command line args provided when invoked.

We make GEF aware of this new command by registering it in the `__main__`
section of the script, by invoking the global function
`register_external_command()`.

Now you have a new GEF command which you can load, either from cli:
```bash
gef➤  source /path/to/newcmd.py
```
or add to your `~/.gdbinit`:
```bash
$ echo source /path/to/newcmd.py >> ~/.gdbinit
```


## Customizing context panes

Sometimes you want something similar to a command to run on each break-like
event and display itself as a part of the GEF context. Here is a simple example
of how to make a custom context pane:

```python
__start_time__ = int(time.time())
def wasted_time_debugging():
    gef_print("You have wasted {} seconds!".format(int(time.time()) - __start_time__))

def wasted_time_debugging_title():
    return "wasted:time:debugging:{}".format(int(time.time()) - __start_time__)

register_external_context_pane("wasted_time_debugging", wasted_time_debugging, wasted_time_debugging_title)
```

Loading it in `GEF` is as easy as loading a command

```
gef➤  source /path/to/custom_context_pane.py
```

It can even be included in the same file as a Command.
Now on each break you will notice a new pane near the bottom of the context.
The order can be modified in the `GEF` context config.

### Context Pane API

The API demonstrated above requires very specific argument types:
`register_external_context_pane(pane_name, display_pane_function, pane_title_function)`

-`pane_name`: a string that will be used as the panes setting name
-`display_pane_function`: a function that uses `gef_print()` to print content
in the pane
-`pane_title_function`: a function that returns the title string or None to hide the title

## API

Some of the most important parts of the API for creating new commands are
mentioned (but not limited to) below. To see the full help of a function, open
GDB and GEF, and use the embedded Python interpreter's `help` command. For
example:

```bash
gef➤  pi help(Architecture)
```

or even from outside GDB:

```bash
$ gdb -q -ex 'pi help(hexdump)' -ex quit
```

The GEF API aims to provide a simpler and more Pythonic approach to GDB's.

Some basic examples:
  - read the memory
```python
gef ➤  pi print(hexdump( gef.memory.read(parse_address("$pc"), length=0x20 )))
0x0000000000000000     f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4    ....1.I..^H..H..
0x0000000000000010     f0 50 54 4c 8d 05 66 0d 01 00 48 8d 0d ef 0c 01    .PTL..f...H.....
```

  - get access to the memory layout
```
gef ➤ pi print('\n'.join([ f"{x.page_start:#x} -> {x.page_end:#x}" for x in gef.memory.maps]))
0x555555554000 -> 0x555555558000
0x555555558000 -> 0x55555556c000
0x55555556c000 -> 0x555555575000
0x555555576000 -> 0x555555577000
0x555555577000 -> 0x555555578000
0x555555578000 -> 0x55555559a000
0x7ffff7cd8000 -> 0x7ffff7cda000
0x7ffff7cda000 -> 0x7ffff7ce1000
0x7ffff7ce1000 -> 0x7ffff7cf2000
0x7ffff7cf2000 -> 0x7ffff7cf7000
[...]
```


The API also offers a number of decorators to simplify the creation of new/existing commands, such as:
  - `@only_if_gdb_running` to execute only if a GDB session is running.
  - `@only_if_gdb_target_local` to check if the target is local i.e. not debugging using GDB `remote`.
  - and many more...


### Reference

For a complete reference of the API offered by GEF, visit [`docs/api/gef.md`](api/gef.md).


### Parsing command arguments

```python
@parse_arguments( {"required_argument_1": DefaultValue1, ...}, {"--optional-argument-1": DefaultValue1, ...} )
```

This decorator aims to facilitate the argument passing to a command. If added, it will use the `argparse` module to parse arguments, and will store them in the `kwargs["arguments"]` of the calling function (therefore the function **must** have `*args, **kwargs` added to its signature). Argument type is inferred directly from the default value **except** for boolean, where a value of `True` corresponds to `argparse`'s `store_true` action. For more details on `argparse`, refer to its Python documentation.

Values given for the parameters also allow list of arguments being past. This can be useful in the case where the number of exact option values is known in advance. This can be achieved simply by using a type of `tuple` or `list` for the default value. `parse_arguments` will determine the type of what to expect based on the first default value of the iterable, so make sure it's not empty. For instance:


```python
@parse_arguments( {"instructions": ["nop", "int3", "hlt"], }, {"--arch": "x64", } )
```


Argument flags are also supported, allowing to write simpler version of the flag such as

```python
@parse_arguments( {}, {("--long-argument", "-l"): value, } )
```

A basic example would be as follow:

```python
class MyCommand(GenericCommand):
    [...]

    @parse_arguments({"foo": [1,]}, {"--bleh": "", ("--blah", "-l): True})
    def do_invoke(self, argv, *args, **kwargs):
      args = kwargs["arguments"]
      if args.foo == 1: ...
      if args.blah == True: ...
```

When the user enters the following command:

```
gef➤ mycommand --blah 3 14 159 2653
```

The function `MyCommand!do_invoke()` can use the command line argument value

```python
args.foo --> [3, 14, 159, 2653] # a List(int) from user input
args.bleh --> "" # the default value
args.blah --> True # set to True because user input declared the option (would have been False otherwise)
```
