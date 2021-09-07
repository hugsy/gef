## Command tmux-setup ##

In the purpose of always making debugging sessions easier while being more
effective, `GEF` integrates two commands:

* `tmux-setup`
* `screen-setup`

Those commands will check whether GDB is being spawn from inside a `tmux`
(resp. `screen`) session, and if so, will split the pane vertically, and
configure the context to be redirected to the new pane, looking something like:

![](https://i.imgur.com/Khk3xGl.png)

To set it up, simply enter

```
gef➤ tmux-setup
```

**Note**: Although `screen-setup` provides a similar setup, the structure of
`screen` does not allow a very clean way to do this. Therefore, if possible, it
would be recommended to use the `tmux-setup` command instead.

### Possible color issues with tmux ###

On Linux tmux only supports 8 colors with some terminal capabilities (`$TERM`
environment variable). This can mess up your color themes when using GEF with
tmux. To remedy this if your terminal supports more colors you can either set
the variable to something like `TERM=screen-256color` or if you don't want or
can't change that variable you can start `tmux` with the `-2` flag to force
tmux to use 256 colors.
