# Extending GEF #

`GEF` intends to provide a battery-included, quickly installable and crazy fast
debugging environment sitting on top of GDB.

But it most importantly provides all the primitives for letting hackers create
their own commands rapidly. Also this page intends to summarize how to create in
2 seconds advanced GDB commands using `GEF` as a library.

_Side note_: [Other projects](https://github.com/pwndbg/pwndbg) accuses `GEF` to
not be easily hackable for new features. This documentation also aims to prove
them wrong.


## Quick start ##

Here is the most basic skeleton for creating a new `GEF` command, named `newcmd`:

```python
class NewCommand(GenericCommand):
    """Dummy one-time command."""
    _cmdline_ = "newcmd"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running                     # not required, only checks if the debug session is started
    def do_invoke(self, argv):
    # do whatever things allowed by gef, for example show the current running
    # architecture as Python object:
    print(" = {}".format(current_arch) )
    # or showing the current $pc
    print("pc = {:#x}".format(current_arch.pc))

if __name__ == "__main__":
    register_external_command( NewCommand() )
```

Yes, that's it!

Loading it by `GEF` is as easy as
```
gef➤  source /path/to/newcmd.py
[+] Loading 'NewCommand'
```

We can call it:
![](https://camo.githubusercontent.com/d41c1c0c0267916f4749800906d201fe5d328db5/687474703a2f2f692e696d6775722e636f6d2f306734416543622e706e67)


## Detailed explainations ##

##### TODO #####

## Live demo ##

Enough theory, let's have a good realistic practice case: create a `ftrace`
command for GDB.

What does an `ftrace` command would do:

  1. receive as argument the name of function to trace,
  1. sets breakpoints on both prologue (to get the function arguments) and
     epilogue to get the return value.
  1. once the function returns, print out all those information
  1. do not halt (i.e. continue execution)

Let's go live:

##### TODO #####


## API ##

Some of the most important API when creating new commands:

### Decorators ###

### Classes ###

### Global Functions ###
