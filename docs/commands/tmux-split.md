## Command `gef tmux-split`

Splits the current `tmux` window so that each context section gets its own dedicated pane,
similar to pwndbg's `splitmind` integration. This is more granular than
[`tmux-setup`](tmux-setup.md), which redirects the entire context to a single side pane.

### Usage

```text
gef tmux-split [SECTION ...] [--layout LAYOUT | --layout-file PATH] [--reset]
```

Three modes:

1. **Flat** — `gef tmux-split [SECTION ...]` spawns one pane per section and applies a
   tmux layout name. With no section arguments the default set is `regs stack code`.
   Sections: `legend`, `regs`, `stack`, `code`, `args`, `memory`, `source`, `trace`,
   `threads`, `extra`. Layout names (`--layout`): `tiled` (default),
   `main-vertical`, `main-horizontal`, `even-horizontal`, `even-vertical`.

2. **Built-in tree layout** — `gef tmux-split --layout pwndbg-classic` reproduces
   pwndbg's default splitmind arrangement: `code` on top (60%), `regs`/`stack`/`trace`
   tiled across the bottom row.

3. **User-defined tree** — `gef tmux-split --layout-file <path.ini>` loads an arbitrary
   layout tree (see [Layout file format](#layout-file-format) below).

`--reset` clears every per-section redirect, kills the panes that GEF spawned, and
collapses back to single-pane mode.

### Examples

Default split (regs / stack / code each in their own pane):

```text
gef➤ gef tmux-split
```

Split only `regs` and `stack`, arranged vertically:

```text
gef➤ gef tmux-split regs stack --layout main-vertical
```

Reproduce pwndbg's classic splitmind layout (code on top, regs/stack/trace below):

```text
gef➤ gef tmux-split --layout pwndbg-classic
```

Use a custom layout file:

```text
gef➤ gef tmux-split --layout-file ~/.config/gef/layout.ini
```

Tear it all down:

```text
gef➤ gef tmux-split --reset
```

### Layout file format

Layout files are INI (parsed via Python's stdlib `configparser`). The format is **flat**
and modeled on splitmind: each pane positions itself relative to a previously declared
pane (or `main`, the user's GDB pane) using one of `right` / `left` / `above` / `below`.

```ini
[layout]
panes = regs, stack, code, trace      ; spawn order matters

[pane.regs]
section = regs                ; defaults to the pane name if omitted
direction = right             ; right | left | above | below
relative_to = main            ; references `main` or any pane declared earlier
size = 50%                    ; size of THIS new pane (% or raw cells/rows); optional

[pane.stack]
direction = below
relative_to = regs
size = 75%

[pane.code]
direction = below
relative_to = stack
size = 66%

[pane.trace]
direction = below
relative_to = code
size = 50%
```

Rules:

* `[layout].panes` lists pane names in spawn order.
* Each `[pane.<name>]` declares one pane.
* `direction` is required and must be one of `right`, `left`, `above`, `below`.
* `relative_to` defaults to `main`. It must reference `main` or a pane declared **earlier**
  in the `panes` list.
* `section` defaults to the pane name; both must be a valid section name.
* `size` is optional. Accepts `<N>%` or raw cells/rows (`<N>`); omit for tmux's default
  even split.
* The same section cannot be bound by more than one pane.
* Errors abort the split before any pane is spawned, with a clear message.

### Generating a starter file

To get a working file you can edit, dump the built-in:

```text
gef➤ gef tmux-split --dump-layout pwndbg-classic ~/.config/gef/layout.ini
```

Then load it after editing:

```text
gef➤ gef tmux-split --layout-file ~/.config/gef/layout.ini
```

### How it works

For each requested section, `gef tmux-split` spawns a tmux pane that publishes its tty
path to a temp file, then sleeps. GEF reads the tty path and writes it into the
`context.output.<section>` setting. From that point on, `ContextCommand` renders that
section directly into the dedicated pane's tty rather than into the main context stream.

The `context.output.<section>` settings are also writable directly — set one to a tty
path you control to route a section anywhere (e.g. another terminal, a fifo). An empty
value (the default) restores normal main-stream rendering for that section.

### Cleanup

Spawned panes are tracked in `gef.session.tmux_panes` and killed automatically:

* on GDB exit (via `atexit`),
* when `gef tmux-split --reset` is invoked,
* when the section's tty disappears mid-session — GEF clears the redirect and recovers.

### Requirements

* You must already be inside a `tmux` session (`$TMUX` set).
* The `tmux` binary must be in `$PATH`.
