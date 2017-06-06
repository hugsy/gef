## Command theme

Customize `GEF` by changing its color scheme.

```
gef➤  theme
context_title_message                   : red bold
default_title_message                   : red bold
default_title_line                      : green bold
context_title_line                      : green bold
disable_color                           : 0
xinfo_title_message                     : blue bold
```

### Changing colors

You have the possibility to change the coloring properties of `GEF` display with
the `theme` command. The command accepts 2 arguments, the name of the property
to update, and its new coloring value.

Colors can be one of the following:

   - red
   - green
   - blue
   - yellow
   - gray
   - pink

Color also accepts the following attributes:

   - bold
   - underline
   - highlight
   - blink

Any other will value simply be ignored.

```
gef➤  theme context_title_message blue bold foobar
gef➤  theme
context_title_message                   : blue bold
default_title_message                   : red bold
default_title_line                      : green bold
context_title_line                      : green bold
disable_color                           : 0
xinfo_title_message                     : blue bold
```
