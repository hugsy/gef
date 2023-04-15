## Command `theme`

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


## Available settings for `theme`


### `theme.context_title_line`

```
theme.context_title_line (str) = "gray"

Description:
	Color of the borders in context window
```


### `theme.context_title_message`

```
theme.context_title_message (str) = "cyan"

Description:
	Color of the title in context window
```


### `theme.default_title_line`

```
theme.default_title_line (str) = "gray"

Description:
	Default color of borders
```


### `theme.default_title_message`

```
theme.default_title_message (str) = "cyan"

Description:
	Default color of title
```


### `theme.table_heading`

```
theme.table_heading (str) = "blue"

Description:
	Color of the column headings to tables (e.g. vmmap)
```


### `theme.old_context`

```
theme.old_context (str) = "gray"

Description:
	Color to use to show things such as code that is not immediately relevant
```


### `theme.disassemble_current_instruction`

```
theme.disassemble_current_instruction (str) = "green"

Description:
	Color to use to highlight the current $pc when disassembling
```


### `theme.dereference_string`

```
theme.dereference_string (str) = "yellow"

Description:
	Color of dereferenced string
```


### `theme.dereference_code`

```
theme.dereference_code (str) = "gray"

Description:
	Color of dereferenced code
```


### `theme.dereference_base_address`

```
theme.dereference_base_address (str) = "cyan"

Description:
	Color of dereferenced address
```


### `theme.dereference_register_value`

```
theme.dereference_register_value (str) = "bold blue"

Description:
	Color of dereferenced register
```


### `theme.registers_register_name`

```
theme.registers_register_name (str) = "blue"

Description:
	Color of the register name in the register window
```


### `theme.registers_value_changed`

```
theme.registers_value_changed (str) = "bold red"

Description:
	Color of the changed register in the register window
```


### `theme.address_stack`

```
theme.address_stack (str) = "pink"

Description:
	Color to use when a stack address is found
```


### `theme.address_heap`

```
theme.address_heap (str) = "green"

Description:
	Color to use when a heap address is found
```


### `theme.address_code`

```
theme.address_code (str) = "red"

Description:
	Color to use when a code address is found
```


### `theme.source_current_line`

```
theme.source_current_line (str) = "green"

Description:
	Color to use for the current code line in the source window
```


