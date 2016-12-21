## Command context ##


![gef-context](https://i.imgur.com/aZiG8Yb.png)


`gef` (not unlike `PEDA` or `fG! famous gdbinit`) provides comprehensive context
menu when hitting a breakpoint.

* The register context box displays current register values. Values in red
  indicate that this register has its value changed since the last
  breakpoint. It makes it convenient to track values. Register values can be
  also accessed and/or dereferenced through the `reg` command.

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

There are currently 6 panes that can be displayed:

   * `regs`
   * `stack`
   * `code`
   * `source`
   * `threads`
   * `trace`

To prevent one pane to be displayed, simply use the `context.layout` setting,
and prepend the pane name with `-` or `!`, such as:

```
gef➤ gef config context.layout "regs stack code -source -threads -trace"
```
Will not display the `source`, `threads`, and `trace` panes.


### Redirecting context output to another tty/file ###

By default, the `gef` context will be displayed on the current TTY. This can be
overridden by setting `context.redirect` variable to have the context sent to
another pane.

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
![gef-context-redirect-pane](https://i.imgur.com/sWlX37q.png)


To go back to normal, remove the value:
```
gef➤ gef config context.redirect ""
```

### Examples ###

  * Display the code pane first, then register, and stack:
```
gef➤ gef config context.layout "code regs stack -source -threads -trace"
```

  * Stop showing the context panes when breaking:
```
gef➤ gef config context.enable 0
```

  * Clear the screen before showing the context panes when breaking:
```
gef➤ gef config context.clear_screen 1
```

  * Automatically dereference the registers in the `regs` pane (like `PEDA`):
```
gef➤ gef config context.show_registers_raw 0
```
