## Command context ##


![gef-context](https://i.imgur.com/aZiG8Yb.png)


`gef` (not unlike `PEDA` or `fG! famous gdbinit`) provides comprehensive context
menu when hitting a breakpoint.

* The register context box displays current register values. Values in red
  indicate that this register has had its value changed since the last
  time execution stopped. It makes it convenient to track values. Register
  values can be also accessed and/or dereferenced through the `reg` command.

* The stack context box shows the 10 (by default but can be tweaked) entries in
  memory pointed by the stack pointer register. If those values are pointers,
  they are successively dereferenced.

* The code context box shows the 10 (by default but can be tweaked) next
  instructions to be executed.


### Editing context layout ###

`gef` allows you to configure your own setup for the display, by re-arranging
the order with which contexts will be displayed.

```
gef➤ gef config context.layout
```

There are currently 6 sections that can be displayed:

   * `regs` : the state of registers
   * `stack` : the content of memory pointed by `$sp` register
   * `code` : the code being executed
   * `source` : if compiled with source, this will show the corresponding line
     of source code
   * `threads` : all the threads
   * `trace` : the execution call trace
   * `extra` : if an automatic behavior is detected (vulnerable format string,
     heap vulnerability, etc.) it will be displayed in this pane
   * `memory` : peek into arbitrary memory locations

To hide a section, simply use the `context.layout` setting, and prepend the
section name with `-` or just omit it.

```
gef➤ gef config context.layout "regs stack code -source -threads -trace extra memory"
```
This configuration will not display the `source`, `threads`, and `trace` sections.

The `memory` pane will display the content of all locations specified by the
`memory` command. For instance,

```
gef➤ memory watch $sp 0x40 byte
```

will print a hexdump version of 0x40 bytes of the stack. This command makes it
convenient for tracking the evolution of arbitrary locations in memory. Tracked
locations can be removed one by one using `memory unwatch`, or altogether with
`memory reset`.

The size of most sections are also customizable:

* `nb_lines_stack` configures how many lines of the stack to show.
* `nb_lines_backtrack` configures how many lines of the backtrace to show.
* `nb_lines_code` and `nb_lines_code_prev` configure how many lines to show
  after and before the PC, respectively.


### Redirecting context output to another tty/file ###

By default, the `gef` context will be displayed on the current TTY. This can be
overridden by setting `context.redirect` variable to have the context sent to
another section.

To do so, select the TTY/file/socket/etc. you want the context redirected to
with `gef config`.

Enter the command `tty` in the prompt:
```
$ tty
/dev/pts/0
```

Then tell `gef` about it!
```
gef➤ gef config context.redirect /dev/pts/0
```

Enjoy:
![gef-context-redirect-section](https://i.imgur.com/sWlX37q.png)


To go back to normal, remove the value:
```
gef➤ gef config context.redirect ""
```

### Examples ###

* Display the code section first, then register, and stack, hiding everything else:
```
gef➤ gef config context.layout "code regs stack"
```

* Stop showing the context sections when breaking:
```
gef➤ gef config context.enable 0
```

* Clear the screen before showing the context sections when breaking:
```
gef➤ gef config context.clear_screen 1
```

* Automatically dereference the registers in the `regs` section:
```
gef➤ gef config context.show_registers_raw 0
```

* Don't 'peek' into the start of functions that are called.
```
gef➤  gef config context.peek_calls False
```

* Hide specific registers from the registers view.
```
gef➤  gef config context.ignore_registers "$cs $ds $gs"
``` 
