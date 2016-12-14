## Command context ##


![gef-x86](https://pbs.twimg.com/media/BvdRAJKIUAA8R6_.png:large)


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

By default, the `gef` context will be displayed on the current TTY. This can be
overridden by setting `context.redirect` variable to have the context sent to
another pane.

![gef-context-redirect-pane](https://i.imgur.com/sWlX37q.png)


