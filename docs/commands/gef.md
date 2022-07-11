## Command `gef`

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

GEF is fully battery-included. However in some rare cases, it is possible that not all commands be loaded. If that's the case the command `gef missing` will detail which command failed to load, along with a (likely) reason. Read the documentation for a solution, or reach out on the Discord.

```
gef➤  gef missing
[*] Command `XXXX` is missing, reason  →  YYYYY.
```


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


### GEF Install Command

`gef install` allows to install one (or more) specific script(s) from `gef-extras`. The new scripts will be downloaded and sourced to be used immediately after by GEF. The syntax is straight forward:

```
gef➤  gef install SCRIPTNAME1 [SCRIPTNAME2...]
```

Where `SCRIPTNAME1` ... are the names of script from the [`gef-extras` repository](https://github.com/hugsy/gef-extras/tree/main/scripts/).


```
gef➤  gef install remote windbg stack
[+] Searching for 'remote.py' in `gef-extras@main`...
[+] Installed file '/tmp/gef/remote.py', new command(s) available: `rpyc-remote`
[+] Searching for 'windbg.py' in `gef-extras@main`...
[+] Installed file '/tmp/gef/windbg.py', new command(s) available: `pt`, `hh`, `tt`, `ptc`, `sxe`, `u`, `xs`, `tc`, `pc`, `g`, `r`
[+] Searching for 'stack.py' in `gef-extras@main`...
[+] Installed file '/tmp/gef/stack.py', new command(s) available: `current-stack-frame`
gef➤
```

This makes it easier to deploy new functionalities in limited environment. By default, the command looks up for script names in the `main` branch of `gef-extras`. However you can change specify a different branch through the `gef.default_branch` configuration setting:

```
gef➤ gef config gef.default_branch dev
```

The files will be dowloaded in the path configured in the `gef.extra_plugins_dir` setting, allowing to reload it easily without having to re-download.

