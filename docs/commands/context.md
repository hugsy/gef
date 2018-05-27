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

   * `legend` : a text explanation of the color code
   * `regs` : the state of registers
   * `stack` : the content of memory pointed by `$sp` register
   * `code` : the code being executed
   * `args` : if stopping at a function calls, print the call arguments
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
gef➤ gef config context.layout "-legend regs stack code args -source -threads -trace extra memory"
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
* `context.nb_lines_threads` determines the number of lines to display inside
  the thread pane. This is convenient when debugging heavily multi-threaded
  applications (apache2, firefox, etc.). It receives an integer as value: if
  this value is `-1` then all threads state will be displayed. Otherwise, if the
  value is set to `N`, then at most `N` thread states will be shown.

To have the stack displayed with the largest stack addresses on top (i.e., grow the
stack downward), enable the following setting:
```
gef➤ gef config context.grow_stack_down True
```

If the saved instruction pointer is not within the portion of the stack being displayed,
then a section is created that includes the saved ip and depending on the architecture
the frame pointer.
```
0x00007fffffffc9e8│+0x00: 0x00007ffff7a2d830  →  <__main+240> mov edi, eax    ($current_frame_savedip)
0x00007fffffffc9e0│+0x00: 0x00000000004008c0  →  <__init+0> push r15    ← $rbp
. . . (440 bytes skipped)
0x00007fffffffc7e8│+0x38: 0x0000000000000000
0x00007fffffffc7e0│+0x30: 0x0000000000000026 ("&"?)
0x00007fffffffc7d8│+0x28: 0x0000000001958ac0
0x00007fffffffc7d0│+0x20: 0x00007ffff7ffa2b0  →  0x5f6f7364765f5f00
0x00007fffffffc7c8│+0x18: 0x00007fff00000000
0x00007fffffffc7c0│+0x10: 0x00007fffffffc950  →  0x0000000000000000
0x00007fffffffc7b8│+0x08: 0x0000000000000000
0x00007fffffffc7b0│+0x00: 0x00007fffffffc7e4  →  0x0000000000000000      ← $rsp
```

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
