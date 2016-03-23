## One command to know them all

All the commands created in the `GEF` are available through the main `help`
menu. Help is available with the command:
```bash
gef> gef help
```

Syntax and description are available by invoking `help` followed by the
command. For example,

```bash
gef> help gef-alias
GEF defined aliases
Syntax: gef-alias (set|show|do|unset)

List of gef-alias subcommands:

gef-alias do -- GEF do alias command
gef-alias set -- GEF add alias command
gef-alias show -- GEF show alias command
gef-alias unset -- GEF remove alias command
```

### Configuration

`gef` can also be configured at runtime through a configuration file locate at
`~/.gef.rc`. To dump the current settings for `GEF`, simply run:

```
gef➤  gef save
[+] Configuration saved to '/home/vagrant/.gef.rc'
```

And to load settings
```
gef➤  gef restore
[+] Configuration from '/home/vagrant/.gef.rc' restored
```

You can then tweak this configuration outside your `gdb` session to suit your
needs.


### Commands

Here are some of the most useful commands available in `GEF`. Have a look at the `Features` section for full explanation.

| Command    | Description |
|:-----------|----------------:|
| `entry-break` | Tries to find best entry point and sets a temporary breakpoint on it. |
| `elf-info` | Display ELF header informations. |
| `aslr` | view/modify GDB ASLR behavior. |
| `checksec` | [Checksec.sh](http://www.trapkit.de/tools/checksec.html) port. |
| `context` | Display execution context. |
|`xinfo` | Get virtual section information for specific address|
|`heap` | Get some information about the Glibc heap structure.|
|`ctf-exploit-templater` | Generates a ready-to-use exploit template for CTF.|
|`deref` | Dereference recursively an address and display information|
|`vmmap` | Display virtual memory mapping|
|`dump-memory` | Dump chunks of memory into raw file on the filesystem. Dump file name template can be defined in GEF runtime config|
|`fd` | Enumerate file descriptors opened by process.|
|`gef-alias` | GEF defined aliases|
|`ksymaddr` | Get kernel address|
|`pattern` | Metasploit-like pattern generation/search|
|`reset-cache` | Reset cache of all stored data.|
|`ropgadget` | [ROPGadget](http://shell-storm.org/project/ROPgadget) plugin|
|`shellcode` | ShellcodeCommand uses [ShellStorm shellcode API](http://shell-storm.org/shellcode/) to search and download shellcodes|
|`trace-run` | Create a runtime trace of all instructions executed from $pc to LOCATION specified.|
|`xfiles` | Shows all libraries (and sections) loaded by binary (Truth is out there).|
|`xor-memory` | XOR a block of memory.|
