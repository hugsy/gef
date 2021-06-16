## Command GEF ##

### GEF Base Command

Displays a list of GEF commands and their descriptions.

```
gef➤  gef                                                                             
─────────────────────────────────── GEF - GDB Enhanced Features ───────────────────────────────────
$                         -- SmartEval: Smart eval (vague approach to mimic WinDBG `?`).
aslr                      -- View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not
                             attached). This command allows to change that setting.   
assemble                  -- Inline code assemble. Architecture can be set in GEF runtime config (default x86-32).  (alias: asm)
bincompare                -- BincompareCommand: compare an binary file with the memory position looking for badchars.
bytearray                 -- BytearrayCommand: Generate a bytearray to be compared with possible badchars.

[...snip...]

```

### GEF Missing Command

Displays the GEF commands which couldn't be loaded, along with the reason for
the issue.

```
gef➤  gef missing
[*] Command `set-permission` is missing, reason  →  Missing `keystone-engine` package, install with: `pip install keystone-engine`.
[*] Command `assemble` is missing, reason  →  Missing `keystone-engine` package for Python, install with: `pip install keystone-engine`.

[...snip...]

```

As it says in the above output, the issues should be resolved by installing the
missing package(s) using pip.

### GEF Config Command

Allows the user to set/view settings for the current debugging session. For
making the changes persistent see the `gef save` entry.

Using `gef config` by itself just shows all of the available settings and their
values.

```
gef➤  gef config
──────────────────────────────────── GEF configuration settings ────────────────────────────────────
context.clear_screen (bool) = False
context.enable (bool) = True
context.grow_stack_down (bool) = False
context.ignore_registers (str) = ""
context.layout (str) = "-code -stack"
context.libc_args (bool) = False

[...snip...]

```

To filter the config settings you can use `gef config [setting]`. 

```
gef➤  gef config theme
─────────────────────────── GEF configuration settings matching 'theme' ───────────────────────────
theme.context_title_line (str) = "gray"
theme.context_title_message (str) = "cyan"
theme.default_title_line (str) = "gray"
theme.default_title_message (str) = "cyan"

[...snip...]

```

You can use `gef config [setting] [value]` to set a setting for the current
session (see example below).

```
gef➤  gef config theme.address_stack blue
```

### GEF Save Command

The `gef save` command saves the current settings (set with `gef config`) to
the user's `~/.gef.rc` file (making the changes persistent). 

```
gef➤  gef save
[+] Configuration saved to '/home/michael/.gef.rc'
```

### GEF Restore Command

Using `gef restore` loads and applies settings from the `~/.gef.rc` file to the
current session. This is useful if you are modifying your GEF configuration
file and want to see the changes without completely reloading GEF. 

```
gef➤  gef restore
[+] Configuration from '/home/michael/.gef.rc' restored
```

### GEF Set Command

The GEF set command allows the user to use GEF context within GDB set commands.
This is useful when you want to make a convenient variable which can be set and
referenced later.

```
gef➤  gef set $a=1
```

### GEF Run Command

The GEF run command is a wrapper around GDB's run command, allowing the user to
use GEF context within the command.

```
gef➤  gef run ./binary
```


