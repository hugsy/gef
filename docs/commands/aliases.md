## Command aliases ##

List the aliases defined by `GEF`.

```
gef➤  aliases
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

### Creating/deleting aliases

`GEF` defines its own aliasing mechanism which overrides the traditional
alias that GDB provides through the built-in command `alias`.

Users can create/modify/delete aliases by editing the `GEF` configuration file,
located at `~/.gef.rc`. The aliases must be in the "`aliases`" section of the
configuration file.

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

Note that many of these aliases are already supported by `GEF` (e.g. `eb`).

Or here are some `PEDA` aliases for people used to using `PEDA` who made the
smart move to `GEF`.

```
# some peda aliases
telescope = dereference
start = entry-break
stack = dereference $sp 10
argv = show args
kp = info stack
findmem = search-pattern
```

The aliases will be loaded next time you load GDB (and `GEF`). Or you can force
`GEF` to reload the settings with the command:

```
gef➤  gef restore
```
