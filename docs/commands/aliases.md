## Command aliases ##

Base command to add, remove, and list `GEF` defined aliases.

```
gef➤  aliases
aliases (add|rm|list)
```

### Adding/Removing Aliases

`GEF` defines its own aliasing mechanism which overrides the traditional
alias that GDB provides through the built-in command `alias`. To add a new alias,
simply use the `aliases add` command. The "command" parameter may contain spaces.

```
aliases add [alias] [command]
```

To remove an alias, simply use the `aliases rm` command.

```
aliases rm [alias]
```

### Listing Aliases

One can list aliases by using the `aliases ls` command. Some sample output of this
command is seen below.

```
[+] Aliases defined:
fmtstr-helper                   →  format-string-helper
telescope                       →  dereference
dps                             →  dereference
dq                              →  hexdump qword
dd                              →  hexdump dword
dw                              →  hexdump word
dc                              →  hexdump byte
cs-dis                          →  capstone-disassemble
ctx                             →  context
start-break                     →  entry-break
ps                              →  process-search
[...]
```

### Using the Configuration File

Users can also create/modify/delete aliases by editing the `GEF` configuration file,
by default located at `~/.gef.rc`. The aliases must be in the `aliases` section
of the configuration file.

Creating a new alias is as simple as creating a new entry in this section:

```
$ nano ~/.gef.rc
[...]
[aliases]
my-new-alias = gdb-or-gef-command <arg1> <arg2> <etc...>
```

#### Bringing some PEDA and WinDBG flavours into GEF

For example, for those (like me) who use WinDBG and like its bindings, they can
be integrated into GDB via GEF aliases like this:

```
$ nano ~/.gef.rc
[...]
[aliases]
# some windbg aliases
dps = dereference
dq = hexdump qword
dd = hexdump dword
dw = hexdump word
dc = hexdump byte
dt = pcustom
bl = info breakpoints
bp = break
be = enable breakpoints
bd = disable breakpoints
bc = delete breakpoints
tbp = tbreak
tba = thbreak
pa = advance
ptc = finish
t = stepi
p = nexti
g = gef run
uf = disassemble
```

Or here are some `PEDA` aliases for people used to using `PEDA` who made the
smart move to `GEF`.

```
# some peda aliases
telescope = dereference
start = entry-break
stack = dereference -l 10 $sp
argv = show args
kp = info stack
findmem = search-pattern
```

The aliases will be loaded next time you load GDB (and `GEF`). Or you can force
`GEF` to reload the settings with the command:

```
gef➤  gef restore
```
