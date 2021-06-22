# Extending GEF #

`GEF` intends to provide a battery-included, quickly installable and crazy fast
debugging environment sitting on top of GDB.

But it most importantly provides all the primitives required to allow hackers to
quickly create their own commands. This page intends to summarize how to
create advanced GDB commands in moments using `GEF` as a library.

A [dedicated repository](https://github.com/hugsy/gef-extras) was born to host
[external scripts](https://github.com/hugsy/gef-extras/tree/master/scripts). This
repo is open to all for contributions, no restrictions and the most valuable
ones will be integrated into `gef.py`.

## Quick start ##

Here is the most basic skeleton for creating a new `GEF` command named `newcmd`:

```python
class NewCommand(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "newcmd"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        # do anything allowed by gef, for example show the current running
        # architecture as Python object:
        print(" = {}".format(current_arch) )
        # or showing the current $pc
        print("pc = {:#x}".format(current_arch.pc))
        return

register_external_command(NewCommand())
```

Yes, that's it!

Loading it in `GEF` is as easy as
```
gef➤  source /path/to/newcmd.py
[+] Loading 'NewCommand'
```

We can call it:

![](https://camo.githubusercontent.com/d41c1c0c0267916f4749800906d201fe5d328db5/687474703a2f2f692e696d6775722e636f6d2f306734416543622e706e67)


## Detailed explanation ##

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

## API ##

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


### Globals ###

```python
register_external_command()
```
Procedure to add the new GEF command

---

```python
current_arch
```
Global variable associated with the architecture of the currently debugged process. The variable is an instance of the `Architecture` class (see below).

---

```python
read_memory(addr, length=0x10)
```
Returns a `length` long byte array with a copy of the process memory read from `addr`.

---

```python
write_memory(addr, buffer, length=0x10)
```
Writes `buffer` to memory at address `addr`.

---

```python
read_int_from_memory(addr)
```

Reads the size of an integer from `addr`, and unpacks it correctly (based on the current arch's endianness)

---

```python
read_cstring_from_memory(addr)
```
Return a NULL-terminated array of bytes, from `addr`.

---

```python
get_register(register_name)
```

Returns the value of given register.

---

```python
get_process_maps()
```
Returns an array of Section objects (see below) corresponding to the current memory layout of the process.

---

```python
gef_disassemble(addr, nb_insn, from_top=False)
```
Disassemble `nb_insn` instructions after `addr`. If `from_top` is False (default), it will also disassemble the `nb_insn` instructions before `addr`. Return an iterator of Instruction objects (see below).

---

```python
ok(msg)
info(msg)
warn(msg)
err(msg)
```

Logging functions

---

```python
gef_on_continue_hook
gef_on_continue_unhook
```
Takes a callback function FUNC as parameter: add/remove a call to `FUNC` when GDB continues execution.

---

```python
gef_on_stop_hook
gef_on_stop_unhook
```

Takes a callback function FUNC as parameter: add/remove a call to `FUNC` when GDB stops execution (breakpoints, watchpoints, interrupt, signal, etc.).

---

```python
gef_on_new_hook
gef_on_new_unhook
```

Takes a callback function FUNC as parameter: add/remove a call to `FUNC` when GDB loads a new binary.

---

```python
gef_on_exit_hook
gef_on_exit_unhook
```

Takes a callback function FUNC as parameter: add/remove a call to `FUNC` when GDB exits an inferior.


### Decorators ###

```python
@only_if_gdb_running
```

Modifies a function to only execute if a GDB session is running. A GDB session is running if:
* a PID exists for the targeted binary
* GDB is running on a coredump of a binary

---

```python
@only_if_gdb_target_local
```
Checks if the current GDB session is local i.e. not debugging using GDB `remote`.

---

```python
@only_if_gdb_version_higher_than( (MAJOR, MINOR) )
```

Checks if the GDB version is higher or equal to the MAJOR and MINOR providedas arguments (both as Integers). This is required since some commands/API ofGDB are only present in the very latest version of GDB.

---

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



### Classes ###

For exhaustive documentation, run
```bash
$ gdb -q -ex 'pi help(<ClassName>)' -ex quit
```

#### Generic ####

New GEF commands **must** inherit `GenericCommand`, have `_cmdline_` and
`_syntax_` attrivutes, and have a instance method `do_invoke(args)` defined.

Other than that, new commands can enjoy all the GEF abstract layer
representation classes, such as:

 * `Instruction` : GEF representation of instruction as pure Python objects.
 * `Address`: GEF representation of memory addresses.
 * `Section`: GEF representation of process memory sections.
 * `Permission`: Page permission object.
 * `Elf`: [ELF](http://www.skyfree.org/linux/references/ELF_Format.pdf) parsing
   object.

#### Architectures ####

 * `Architecture`  : Generic metaclass for the architectures supported by GEF.
 * `ARM`
 * `AARCH64`
 * `X86`
 * `X86_64`
 * `PowerPC`
 * `PowerPC64`
 * `SPARC`
 * `SPARC64`
 * `MIPS`


#### Heap ####

 * `GlibcArena` : Glibc arena class
 * `GlibcChunk` : Glibc chunk class.
