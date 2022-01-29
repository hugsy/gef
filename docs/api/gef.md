<!-- markdownlint-disable -->

# <kbd>module</kbd> `GEF`




**Global Variables**
---------------
- **GDB_MIN_VERSION**
- **GDB_VERSION**
- **PYTHON_MIN_VERSION**
- **PYTHON_VERSION**
- **DEFAULT_PAGE_ALIGN_SHIFT**
- **DEFAULT_PAGE_SIZE**
- **GEF_TEMP_DIR**
- **GEF_MAX_STRING_LENGTH**
- **LIBC_HEAP_MAIN_ARENA_DEFAULT_NAME**
- **ANSI_SPLIT_RE**
- **LEFT_ARROW**
- **RIGHT_ARROW**
- **DOWN_ARROW**
- **HORIZONTAL_LINE**
- **VERTICAL_LINE**
- **CROSS**
- **TICK**
- **BP_GLYPH**
- **GEF_PROMPT**
- **GEF_PROMPT_ON**
- **GEF_PROMPT_OFF**
- **PATTERN_LIBC_VERSION**
- **gef**
- **PREFIX**
- **gdb_initial_settings**
- **cmd**

---

<a href="https://cs.github.com/hugsy/gef?q=http_get"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `http_get`

```python
http_get(url: str) → Union[bytes, NoneType]
```

Basic HTTP wrapper for GET request. Return the body of the page if HTTP code is OK, otherwise return None. 


---

<a href="https://cs.github.com/hugsy/gef?q=update_gef"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `update_gef`

```python
update_gef(argv: List[str]) → int
```

Try to update `gef` to the latest version pushed on GitHub master branch. Return 0 on success, 1 on failure.  


---

<a href="https://cs.github.com/hugsy/gef?q=reset_all_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `reset_all_caches`

```python
reset_all_caches() → None
```

Free all caches. If an object is cached, it will have a callable attribute `cache_clear` which will be invoked to purge the function cache. 


---

<a href="https://cs.github.com/hugsy/gef?q=reset"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `reset`

```python
reset() → None
```






---

<a href="https://cs.github.com/hugsy/gef?q=highlight_text"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `highlight_text`

```python
highlight_text(text: str) → str
```

Highlight text using gef.ui.highlight_table { match -> color } settings. 

If RegEx is enabled it will create a match group around all items in the gef.ui.highlight_table and wrap the specified color in the gef.ui.highlight_table around those matches. 

If RegEx is disabled, split by ANSI codes and 'colorify' each match found within the specified string. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_print"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_print`

```python
gef_print(*args: str, end='\n', sep=' ', **kwargs: Any) → None
```

Wrapper around print(), using string buffering feature. 


---

<a href="https://cs.github.com/hugsy/gef?q=bufferize"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `bufferize`

```python
bufferize(f: Callable) → Callable
```

Store the content to be printed for a function in memory, and flush it on function exit. 


---

<a href="https://cs.github.com/hugsy/gef?q=p8"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p8`

```python
p8(x: int, s: bool = False) → bytes
```

Pack one byte respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=p16"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p16`

```python
p16(x: int, s: bool = False) → bytes
```

Pack one word respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=p32"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p32`

```python
p32(x: int, s: bool = False) → bytes
```

Pack one dword respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=p64"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p64`

```python
p64(x: int, s: bool = False) → bytes
```

Pack one qword respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=u8"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u8`

```python
u8(x: bytes, s: bool = False) → int
```

Unpack one byte respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=u16"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u16`

```python
u16(x: bytes, s: bool = False) → int
```

Unpack one word respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=u32"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u32`

```python
u32(x: bytes, s: bool = False) → int
```

Unpack one dword respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=u64"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u64`

```python
u64(x: bytes, s: bool = False) → int
```

Unpack one qword respecting the current architecture endianness. 


---

<a href="https://cs.github.com/hugsy/gef?q=is_ascii_string"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_ascii_string`

```python
is_ascii_string(address: int) → bool
```

Helper function to determine if the buffer pointed by `address` is an ASCII string (in GDB) 


---

<a href="https://cs.github.com/hugsy/gef?q=is_alive"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_alive`

```python
is_alive() → bool
```

Check if GDB is running. 


---

<a href="https://cs.github.com/hugsy/gef?q=only_if_gdb_running"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_gdb_running`

```python
only_if_gdb_running(f: Callable) → Callable
```

Decorator wrapper to check if GDB is running. 


---

<a href="https://cs.github.com/hugsy/gef?q=only_if_gdb_target_local"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_gdb_target_local`

```python
only_if_gdb_target_local(f: Callable) → Callable
```

Decorator wrapper to check if GDB is running locally (target not remote). 


---

<a href="https://cs.github.com/hugsy/gef?q=deprecated"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `deprecated`

```python
deprecated(solution: str = '') → Callable
```

Decorator to add a warning when a command is obsolete and will be removed. 


---

<a href="https://cs.github.com/hugsy/gef?q=experimental_feature"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `experimental_feature`

```python
experimental_feature(f: Callable) → Callable
```

Decorator to add a warning when a feature is experimental. 


---

<a href="https://cs.github.com/hugsy/gef?q=only_if_gdb_version_higher_than"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_gdb_version_higher_than`

```python
only_if_gdb_version_higher_than(
    required_gdb_version: Tuple[int, ...]
) → Callable
```

Decorator to check whether current GDB version requirements. 


---

<a href="https://cs.github.com/hugsy/gef?q=only_if_current_arch_in"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_current_arch_in`

```python
only_if_current_arch_in(
    valid_architectures: List[ForwardRef('Architecture')]
) → Callable
```

Decorator to allow commands for only a subset of the architectured supported by GEF. This decorator is to use lightly, as it goes against the purpose of GEF to support all architectures GDB does. However in some cases, it is necessary. 


---

<a href="https://cs.github.com/hugsy/gef?q=only_if_events_supported"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_events_supported`

```python
only_if_events_supported(event_type: str) → Callable
```

Checks if GDB supports events without crashing. 


---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=wrapped_f"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Any, **kwargs: Any) → Any
```






---

<a href="https://cs.github.com/hugsy/gef?q=FakeExit"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FakeExit`

```python
FakeExit(*args: Any, **kwargs: Any) → NoReturn
```






---

<a href="https://cs.github.com/hugsy/gef?q=parse_arguments"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_arguments`

```python
parse_arguments(
    required_arguments: Dict[Union[str, Tuple[str, str]], Any],
    optional_arguments: Dict[Union[str, Tuple[str, str]], Any]
) → Union[Callable, NoneType]
```

Argument parsing decorator. 


---

<a href="https://cs.github.com/hugsy/gef?q=titlify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `titlify`

```python
titlify(
    text: str,
    color: Optional[str] = None,
    msg_color: Optional[str] = None
) → str
```

Print a centered title. 


---

<a href="https://cs.github.com/hugsy/gef?q=err"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `err`

```python
err(msg: str) → None
```






---

<a href="https://cs.github.com/hugsy/gef?q=warn"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `warn`

```python
warn(msg: str) → None
```






---

<a href="https://cs.github.com/hugsy/gef?q=ok"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ok`

```python
ok(msg: str) → None
```






---

<a href="https://cs.github.com/hugsy/gef?q=info"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `info`

```python
info(msg: str) → None
```






---

<a href="https://cs.github.com/hugsy/gef?q=push_context_message"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `push_context_message`

```python
push_context_message(level: str, message: str) → None
```

Push the message to be displayed the next time the context is invoked. 


---

<a href="https://cs.github.com/hugsy/gef?q=show_last_exception"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `show_last_exception`

```python
show_last_exception() → None
```

Display the last Python exception. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_pystring"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_pystring`

```python
gef_pystring(x: bytes) → str
```

Returns a sanitized version as string of the bytes list given in input. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_pybytes"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_pybytes`

```python
gef_pybytes(x: str) → bytes
```

Returns an immutable bytes list from the string given as input. 


---

<a href="https://cs.github.com/hugsy/gef?q=style_byte"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `style_byte`

```python
style_byte(b: int, color: bool = True) → str
```






---

<a href="https://cs.github.com/hugsy/gef?q=hexdump"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `hexdump`

```python
hexdump(
    source: ByteString,
    length: int = 16,
    separator: str = '.',
    show_raw: bool = False,
    show_symbol: bool = True,
    base: int = 0
) → str
```

Return the hexdump of `src` argument. @param source *MUST* be of type bytes or bytearray @param length is the length of items per line @param separator is the default character to use if one byte is not printable @param show_raw if True, do not add the line nor the text translation @param base is the start address of the block being hexdump @return a string with the hexdump 


---

<a href="https://cs.github.com/hugsy/gef?q=is_debug"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_debug`

```python
is_debug() → bool
```

Check if debug mode is enabled. 


---

<a href="https://cs.github.com/hugsy/gef?q=hide_context"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `hide_context`

```python
hide_context() → bool
```

Helper function to hide the context pane. 


---

<a href="https://cs.github.com/hugsy/gef?q=unhide_context"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `unhide_context`

```python
unhide_context() → bool
```

Helper function to unhide the context pane. 


---

<a href="https://cs.github.com/hugsy/gef?q=enable_redirect_output"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `enable_redirect_output`

```python
enable_redirect_output(to_file: str = '/dev/null') → None
```

Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`. 


---

<a href="https://cs.github.com/hugsy/gef?q=disable_redirect_output"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `disable_redirect_output`

```python
disable_redirect_output() → None
```

Disable the output redirection, if any. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_makedirs"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_makedirs`

```python
gef_makedirs(path: str, mode: int = 493) → Path
```

Recursive mkdir() creation. If successful, return the absolute path of the directory created. 


---

<a href="https://cs.github.com/hugsy/gef?q=gdb_disassemble"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gdb_disassemble`

```python
gdb_disassemble(
    start_pc: int,
    **kwargs: int
) → Generator[__main__.Instruction, NoneType, NoneType]
```

Disassemble instructions from `start_pc` (Integer). Accepts the following named parameters: 
- `end_pc` (Integer) only instructions whose start address fall in the interval from start_pc to end_pc are returned. 
- `count` (Integer) list at most this many disassembled instructions If `end_pc` and `count` are not provided, the function will behave as if `count=1`. Return an iterator of Instruction objects 


---

<a href="https://cs.github.com/hugsy/gef?q=gdb_get_nth_previous_instruction_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gdb_get_nth_previous_instruction_address`

```python
gdb_get_nth_previous_instruction_address(
    addr: int,
    n: int
) → Union[int, NoneType]
```

Return the address (Integer) of the `n`-th instruction before `addr`. 


---

<a href="https://cs.github.com/hugsy/gef?q=gdb_get_nth_next_instruction_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gdb_get_nth_next_instruction_address`

```python
gdb_get_nth_next_instruction_address(addr: int, n: int) → int
```

Return the address (Integer) of the `n`-th instruction after `addr`. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_instruction_n"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_instruction_n`

```python
gef_instruction_n(addr: int, n: int) → Instruction
```

Return the `n`-th instruction after `addr` as an Instruction object. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_get_instruction_at"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_get_instruction_at`

```python
gef_get_instruction_at(addr: int) → Instruction
```

Return the full Instruction found at the specified address. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_current_instruction"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_current_instruction`

```python
gef_current_instruction(addr: int) → Instruction
```

Return the current instruction as an Instruction object. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_next_instruction"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_next_instruction`

```python
gef_next_instruction(addr: int) → Instruction
```

Return the next instruction as an Instruction object. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_disassemble"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_disassemble`

```python
gef_disassemble(
    addr: int,
    nb_insn: int,
    nb_prev: int = 0
) → Generator[__main__.Instruction, NoneType, NoneType]
```

Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`. Return an iterator of Instruction objects. 


---

<a href="https://cs.github.com/hugsy/gef?q=capstone_disassemble"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `capstone_disassemble`

```python
capstone_disassemble(
    location: int,
    nb_insn: int,
    **kwargs: Any
) → Generator[__main__.Instruction, NoneType, NoneType]
```

Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr` using the Capstone-Engine disassembler, if available. Return an iterator of Instruction objects. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_execute_external"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_execute_external`

```python
gef_execute_external(
    command: Sequence[str],
    as_list: bool = False,
    **kwargs: Any
) → Union[str, List[str]]
```

Execute an external command and return the result. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_execute_gdb_script"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_execute_gdb_script`

```python
gef_execute_gdb_script(commands: str) → None
```

Execute the parameter `source` as GDB command. This is done by writing `commands` to a temporary file, which is then executed via GDB `source` command. The tempfile is then deleted. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_entry_point"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_entry_point`

```python
get_entry_point() → Union[int, NoneType]
```

Return the binary entry point. `get_entry_point` is **DEPRECATED** and will be removed in the future. Use `gef.binary.entry_point` instead 


---

<a href="https://cs.github.com/hugsy/gef?q=is_pie"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_pie`

```python
is_pie(fpath: str) → bool
```






---

<a href="https://cs.github.com/hugsy/gef?q=is_big_endian"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_big_endian`

```python
is_big_endian() → bool
```

`is_big_endian` is **DEPRECATED** and will be removed in the future. Prefer `gef.arch.endianness == Endianness.BIG_ENDIAN` 


---

<a href="https://cs.github.com/hugsy/gef?q=is_little_endian"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_little_endian`

```python
is_little_endian() → bool
```

`is_little_endian` is **DEPRECATED** and will be removed in the future. gef.arch.endianness == Endianness.LITTLE_ENDIAN 


---

<a href="https://cs.github.com/hugsy/gef?q=flags_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `flags_to_human`

```python
flags_to_human(reg_value: int, value_table: Dict[int, str]) → str
```

Return a human readable string showing the flag states. 


---

<a href="https://cs.github.com/hugsy/gef?q=register_architecture"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_architecture`

```python
register_architecture(
    cls: Type[ForwardRef('Architecture')]
) → Type[ForwardRef('Architecture')]
```

Class decorator for declaring an architecture to GEF. 


---

<a href="https://cs.github.com/hugsy/gef?q=copy_to_clipboard"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `copy_to_clipboard`

```python
copy_to_clipboard(data: str) → None
```

Helper function to submit data to the clipboard 


---

<a href="https://cs.github.com/hugsy/gef?q=use_stdtype"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_stdtype`

```python
use_stdtype() → str
```






---

<a href="https://cs.github.com/hugsy/gef?q=use_default_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_default_type`

```python
use_default_type() → str
```






---

<a href="https://cs.github.com/hugsy/gef?q=use_golang_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_golang_type`

```python
use_golang_type() → str
```






---

<a href="https://cs.github.com/hugsy/gef?q=use_rust_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_rust_type`

```python
use_rust_type() → str
```






---

<a href="https://cs.github.com/hugsy/gef?q=to_unsigned_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `to_unsigned_long`

```python
to_unsigned_long(v: gdb.Value) → int
```

Cast a gdb.Value to unsigned long. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_path_from_info_proc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_path_from_info_proc`

```python
get_path_from_info_proc() → Union[str, NoneType]
```






---

<a href="https://cs.github.com/hugsy/gef?q=get_os"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_os`

```python
get_os() → str
```

`get_os` is **DEPRECATED** and will be removed in the future. Use `gef.session.os` 


---

<a href="https://cs.github.com/hugsy/gef?q=download_file"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `download_file`

```python
download_file(
    remote_path: str,
    use_cache: bool = False,
    local_name: Optional[str] = None
) → Union[str, NoneType]
```

Download filename `remote_path` inside the mirror tree inside the `gef.config["gef.tempdir"]`. The tree architecture must be `gef.config["gef.tempdir"]/gef/<local_pid>/<remote_filepath>`. This allow a "chroot-like" tree format. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_function_length"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_function_length`

```python
get_function_length(sym: str) → int
```

Attempt to get the length of the raw bytes of a function. 


---

<a href="https://cs.github.com/hugsy/gef?q=process_lookup_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `process_lookup_address`

```python
process_lookup_address(address: int) → Union[__main__.Section, NoneType]
```

Look up for an address in memory. Return an Address object if found, None otherwise. 


---

<a href="https://cs.github.com/hugsy/gef?q=xor"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `xor`

```python
xor(data: ByteString, key: str) → bytearray
```

Return `data` xor-ed with `key`. 


---

<a href="https://cs.github.com/hugsy/gef?q=is_hex"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_hex`

```python
is_hex(pattern: str) → bool
```

Return whether provided string is a hexadecimal value. 


---

<a href="https://cs.github.com/hugsy/gef?q=ida_synchronize_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ida_synchronize_handler`

```python
ida_synchronize_handler(_: 'gdb.Event') → None
```






---

<a href="https://cs.github.com/hugsy/gef?q=continue_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `continue_handler`

```python
continue_handler(_: 'gdb.Event') → None
```

GDB event handler for new object continue cases. 


---

<a href="https://cs.github.com/hugsy/gef?q=hook_stop_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `hook_stop_handler`

```python
hook_stop_handler(_: 'gdb.Event') → None
```

GDB event handler for stop cases. 


---

<a href="https://cs.github.com/hugsy/gef?q=new_objfile_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `new_objfile_handler`

```python
new_objfile_handler(_: 'gdb.Event') → None
```

GDB event handler for new object file cases. 


---

<a href="https://cs.github.com/hugsy/gef?q=exit_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `exit_handler`

```python
exit_handler(_: 'gdb.Event') → None
```

GDB event handler for exit cases. 


---

<a href="https://cs.github.com/hugsy/gef?q=memchanged_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `memchanged_handler`

```python
memchanged_handler(_: 'gdb.Event') → None
```

GDB event handler for mem changes cases. 


---

<a href="https://cs.github.com/hugsy/gef?q=regchanged_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `regchanged_handler`

```python
regchanged_handler(_: 'gdb.Event') → None
```

GDB event handler for reg changes cases. 


---

<a href="https://cs.github.com/hugsy/gef?q=load_libc_args"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `load_libc_args`

```python
load_libc_args() → bool
```

Load the LIBC function arguments. Returns `True` on success, `False` or an Exception otherwise. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_terminal_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_terminal_size`

```python
get_terminal_size() → Tuple[int, int]
```

Return the current terminal size. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_generic_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_generic_arch`

```python
get_generic_arch(
    module: module,
    prefix: str,
    arch: str,
    mode: Optional[str],
    big_endian: Optional[bool],
    to_string: bool = False
) → Tuple[str, Union[int, str]]
```

Retrieves architecture and mode from the arguments for use for the holy {cap,key}stone/unicorn trinity. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_generic_running_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_generic_running_arch`

```python
get_generic_running_arch(
    module: module,
    prefix: str,
    to_string: bool = False
) → Union[Tuple[NoneType, NoneType], Tuple[str, Union[int, str]]]
```

Retrieves architecture and mode from the current context. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_unicorn_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_unicorn_arch`

```python
get_unicorn_arch(
    arch: Optional[str] = None,
    mode: Optional[str] = None,
    endian: Optional[bool] = None,
    to_string: bool = False
) → Union[Tuple[NoneType, NoneType], Tuple[str, Union[int, str]]]
```






---

<a href="https://cs.github.com/hugsy/gef?q=get_capstone_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_capstone_arch`

```python
get_capstone_arch(
    arch: Optional[str] = None,
    mode: Optional[str] = None,
    endian: Optional[bool] = None,
    to_string: bool = False
) → Union[Tuple[NoneType, NoneType], Tuple[str, Union[int, str]]]
```






---

<a href="https://cs.github.com/hugsy/gef?q=get_keystone_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_keystone_arch`

```python
get_keystone_arch(
    arch: Optional[str] = None,
    mode: Optional[str] = None,
    endian: Optional[bool] = None,
    to_string: bool = False
) → Union[Tuple[NoneType, NoneType], Tuple[str, Union[int, str]]]
```






---

<a href="https://cs.github.com/hugsy/gef?q=get_unicorn_registers"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_unicorn_registers`

```python
get_unicorn_registers(
    to_string: bool = False
) → Union[Dict[str, int], Dict[str, str]]
```

Return a dict matching the Unicorn identifier for a specific register. 


---

<a href="https://cs.github.com/hugsy/gef?q=keystone_assemble"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `keystone_assemble`

```python
keystone_assemble(
    code: str,
    arch: int,
    mode: int,
    **kwargs: Any
) → Union[str, bytearray, NoneType]
```

Assembly encoding function based on keystone. 


---

<a href="https://cs.github.com/hugsy/gef?q=reset_architecture"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `reset_architecture`

```python
reset_architecture(
    arch: Optional[str] = None,
    default: Optional[str] = None
) → None
```

Sets the current architecture. If an arch is explicitly specified, use that one, otherwise try to parse it out of the current target. If that fails, and default is specified, select and set that arch. Raise an exception if the architecture cannot be set.  Does not return a value. 


---

<a href="https://cs.github.com/hugsy/gef?q=get_memory_alignment"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_memory_alignment`

```python
get_memory_alignment(in_bits: bool = False) → int
```

Try to determine the size of a pointer on this system.  First, try to parse it out of the ELF header.  Next, use the size of `size_t`.  Finally, try the size of $pc.  If `in_bits` is set to True, the result is returned in bits, otherwise in  bytes. `get_memory_alignment` is **DEPRECATED** and will be removed in the future. Use `gef.arch.ptrsize` instead 


---

<a href="https://cs.github.com/hugsy/gef?q=clear_screen"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `clear_screen`

```python
clear_screen(tty: str = '') → None
```

Clear the screen. 


---

<a href="https://cs.github.com/hugsy/gef?q=format_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `format_address`

```python
format_address(addr: int) → str
```

Format the address according to its size. 


---

<a href="https://cs.github.com/hugsy/gef?q=format_address_spaces"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `format_address_spaces`

```python
format_address_spaces(addr: int, left: bool = True) → str
```

Format the address according to its size, but with spaces instead of zeroes. 


---

<a href="https://cs.github.com/hugsy/gef?q=align_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `align_address`

```python
align_address(address: int) → int
```

Align the provided address to the process's native length. 


---

<a href="https://cs.github.com/hugsy/gef?q=align_address_to_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `align_address_to_size`

```python
align_address_to_size(address: int, align: int) → int
```

Align the address to the given size. 


---

<a href="https://cs.github.com/hugsy/gef?q=align_address_to_page"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `align_address_to_page`

```python
align_address_to_page(address: int) → int
```

Align the address to a page. 


---

<a href="https://cs.github.com/hugsy/gef?q=malloc_align_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `malloc_align_address`

```python
malloc_align_address(address: int) → int
```

Align addresses according to glibc's MALLOC_ALIGNMENT. See also Issue #689 on Github 


---

<a href="https://cs.github.com/hugsy/gef?q=parse_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_address`

```python
parse_address(address: str) → int
```

Parse an address and return it as an Integer. 


---

<a href="https://cs.github.com/hugsy/gef?q=is_in_x86_kernel"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_in_x86_kernel`

```python
is_in_x86_kernel(address: int) → bool
```






---

<a href="https://cs.github.com/hugsy/gef?q=de_bruijn"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `de_bruijn`

```python
de_bruijn(alphabet: bytes, n: int) → Generator[str, NoneType, NoneType]
```

De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib). 


---

<a href="https://cs.github.com/hugsy/gef?q=generate_cyclic_pattern"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `generate_cyclic_pattern`

```python
generate_cyclic_pattern(length: int, cycle: int = 4) → bytearray
```

Create a `length` byte bytearray of a de Bruijn cyclic pattern. 


---

<a href="https://cs.github.com/hugsy/gef?q=safe_parse_and_eval"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `safe_parse_and_eval`

```python
safe_parse_and_eval(value: str) → Union[ForwardRef('gdb.Value'), NoneType]
```

GEF wrapper for gdb.parse_and_eval(): this function returns None instead of raising gdb.error if the eval failed. 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_convenience"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_convenience`

```python
gef_convenience(value: str) → str
```

Defines a new convenience value. 


---

<a href="https://cs.github.com/hugsy/gef?q=parse_string_range"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_string_range`

```python
parse_string_range(s: str) → Iterator[int]
```

Parses an address range (e.g. 0x400000-0x401000) 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_get_pie_breakpoint"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_get_pie_breakpoint`

```python
gef_get_pie_breakpoint(num: int) → PieVirtualBreakpoint
```

`gef_get_pie_breakpoint` is **DEPRECATED** and will be removed in the future. Use `gef.session.pie_breakpoints[num]` 


---

<a href="https://cs.github.com/hugsy/gef?q=endian_str"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `endian_str`

```python
endian_str() → str
```

`endian_str` is **DEPRECATED** and will be removed in the future. Use `str(gef.arch.endianness)` instead 


---

<a href="https://cs.github.com/hugsy/gef?q=get_gef_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_gef_setting`

```python
get_gef_setting(name: str) → Any
```

`get_gef_setting` is **DEPRECATED** and will be removed in the future. Use `gef.config[key]` 


---

<a href="https://cs.github.com/hugsy/gef?q=set_gef_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `set_gef_setting`

```python
set_gef_setting(name: str, value: Any) → None
```

`set_gef_setting` is **DEPRECATED** and will be removed in the future. Use `gef.config[key] = value` 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_getpagesize"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_getpagesize`

```python
gef_getpagesize() → int
```

`gef_getpagesize` is **DEPRECATED** and will be removed in the future. Use `gef.session.pagesize` 


---

<a href="https://cs.github.com/hugsy/gef?q=gef_read_canary"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_read_canary`

```python
gef_read_canary() → Union[Tuple[int, int], NoneType]
```

`gef_read_canary` is **DEPRECATED** and will be removed in the future. Use `gef.session.canary` 


---

<a href="https://cs.github.com/hugsy/gef?q=get_pid"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_pid`

```python
get_pid() → int
```

`get_pid` is **DEPRECATED** and will be removed in the future. Use `gef.session.pid` 


---

<a href="https://cs.github.com/hugsy/gef?q=get_filename"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_filename`

```python
get_filename() → str
```

`get_filename` is **DEPRECATED** and will be removed in the future. Use `gef.session.file.name` 


---

<a href="https://cs.github.com/hugsy/gef?q=get_glibc_arena"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_glibc_arena`

```python
get_glibc_arena() → Union[__main__.GlibcArena, NoneType]
```

`get_glibc_arena` is **DEPRECATED** and will be removed in the future. Use `gef.heap.main_arena` 


---

<a href="https://cs.github.com/hugsy/gef?q=get_register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_register`

```python
get_register(regname) → Union[int, NoneType]
```

`get_register` is **DEPRECATED** and will be removed in the future. Use `gef.arch.register(regname)` 


---

<a href="https://cs.github.com/hugsy/gef?q=get_process_maps"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_process_maps`

```python
get_process_maps() → List[__main__.Section]
```

`get_process_maps` is **DEPRECATED** and will be removed in the future. Use `gef.memory.maps` 


---

<a href="https://cs.github.com/hugsy/gef?q=set_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `set_arch`

```python
set_arch(arch: Optional[str] = None, default: Optional[str] = None) → None
```

`set_arch` is **DEPRECATED** and will be removed in the future. Use `reset_architecture` 


---

<a href="https://cs.github.com/hugsy/gef?q=register_external_context_pane"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_external_context_pane`

```python
register_external_context_pane(
    pane_name: str,
    display_pane_function: Callable[[], NoneType],
    pane_title_function: Callable[[], Optional[str]]
) → None
```

Registering function for new GEF Context View. pane_name: a string that has no spaces (used in settings) display_pane_function: a function that uses gef_print() to print strings pane_title_function: a function that returns a string or None, which will be displayed as the title. If None, no title line is displayed. 

Example Usage: def display_pane(): gef_print("Wow, I am a context pane!") def pane_title(): return "example:pane" register_external_context_pane("example_pane", display_pane, pane_title) 


---

<a href="https://cs.github.com/hugsy/gef?q=register_external_command"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_external_command`

```python
register_external_command(
    obj: 'GenericCommand'
) → Type[ForwardRef('GenericCommand')]
```

Registering function for new GEF (sub-)command to GDB. 


---

<a href="https://cs.github.com/hugsy/gef?q=register_command"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_command`

```python
register_command(
    cls: Type[ForwardRef('GenericCommand')]
) → Type[ForwardRef('GenericCommand')]
```

Decorator for registering new GEF (sub-)command to GDB. 


---

<a href="https://cs.github.com/hugsy/gef?q=register_priority_command"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_priority_command`

```python
register_priority_command(
    cls: Type[ForwardRef('GenericCommand')]
) → Type[ForwardRef('GenericCommand')]
```

Decorator for registering new command with priority, meaning that it must loaded before the other generic commands. 


---

<a href="https://cs.github.com/hugsy/gef?q=register_function"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_function`

```python
register_function(
    cls: Type[ForwardRef('GenericFunction')]
) → Type[ForwardRef('GenericFunction')]
```

Decorator for registering a new convenience function to GDB. 


---

## <kbd>class</kbd> `AARCH64`





---

#### <kbd>property</kbd> AARCH64.fp





---

#### <kbd>property</kbd> AARCH64.instruction_length





---

#### <kbd>property</kbd> AARCH64.pc





---

#### <kbd>property</kbd> AARCH64.registers





---

#### <kbd>property</kbd> AARCH64.sp







---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.is_thumb"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.is_thumb`

```python
is_thumb() → bool
```

Determine if the machine is currently in THUMB mode. 

---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=AARCH64.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AARCH64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `ARM`





---

#### <kbd>property</kbd> ARM.fp





---

#### <kbd>property</kbd> ARM.instruction_length





---

#### <kbd>property</kbd> ARM.mode





---

#### <kbd>property</kbd> ARM.pc





---

#### <kbd>property</kbd> ARM.ptrsize





---

#### <kbd>property</kbd> ARM.registers





---

#### <kbd>property</kbd> ARM.sp







---

<a href="https://cs.github.com/hugsy/gef?q=ARM.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=ARM.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.is_thumb"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.is_thumb`

```python
is_thumb() → bool
```

Determine if the machine is currently in THUMB mode. 

---

<a href="https://cs.github.com/hugsy/gef?q=ARM.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=ARM.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ARM.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `ASLRCommand`
View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not attached). This command allows to change that setting. 

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> ASLRCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ASLRCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ASLRCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Address`
GEF representation of memory addresses. 

<a href="https://cs.github.com/hugsy/gef?q=Address.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Address.__init__`

```python
__init__(**kwargs: Any) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=Address.dereference"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Address.dereference`

```python
dereference() → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=Address.is_in_heap_segment"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Address.is_in_heap_segment`

```python
is_in_heap_segment() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Address.is_in_stack_segment"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Address.is_in_stack_segment`

```python
is_in_stack_segment() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Address.is_in_text_segment"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Address.is_in_text_segment`

```python
is_in_text_segment() → bool
```






---

## <kbd>class</kbd> `AliasesAddCommand`
Command to add aliases. 

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesAddCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesAddCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesAddCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `AliasesCommand`
Base command to add, remove, or list aliases. 

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `AliasesListCommand`
Command to list aliases. 

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesListCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesListCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `AliasesRmCommand`
Command to remove aliases. 

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesRmCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AliasesRmCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AliasesRmCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Architecture`
Generic metaclass for the architecture supported by GEF. 


---

#### <kbd>property</kbd> Architecture.endianness





---

#### <kbd>property</kbd> Architecture.fp





---

#### <kbd>property</kbd> Architecture.pc





---

#### <kbd>property</kbd> Architecture.ptrsize





---

#### <kbd>property</kbd> Architecture.registers





---

#### <kbd>property</kbd> Architecture.sp







---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Architecture.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Architecture.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `AssembleCommand`
Inline code assemble. Architecture can be set in GEF runtime config.  

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AssembleCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.list_archs"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.list_archs`

```python
list_archs() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=AssembleCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `AssembleCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `BssBaseFunction`
Return the current bss base address plus the given offset. 

<a href="https://cs.github.com/hugsy/gef?q=BssBaseFunction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `BssBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=BssBaseFunction.arg_to_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `BssBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=BssBaseFunction.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `BssBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=BssBaseFunction.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `BssBaseFunction.invoke`

```python
invoke(*args: Any) → int
```






---

## <kbd>class</kbd> `CanaryCommand`
Shows the canary value of the current process. 

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> CanaryCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CanaryCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CanaryCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `CapstoneDisassembleCommand`
Use capstone disassembly framework to disassemble code. 

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> CapstoneDisassembleCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.capstone_analyze_pc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.capstone_analyze_pc`

```python
capstone_analyze_pc(insn: __main__.Instruction, nb_insn: int) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=CapstoneDisassembleCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `CapstoneDisassembleCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ChangeFdCommand`
ChangeFdCommand: redirect file descriptor during runtime. 

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> ChangeFdCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.get_fd_from_result"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.get_fd_from_result`

```python
get_fd_from_result(res: str) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangeFdCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangeFdCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ChangePermissionBreakpoint`
When hit, this temporary breakpoint will restore the original code, and position $pc correctly. 

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionBreakpoint.__init__`

```python
__init__(loc: str, code: ByteString, pc: int) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `ChangePermissionCommand`
Change a page permission. By default, it will change it to 7 (RWX). 

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ChangePermissionCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.get_stub_by_arch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.get_stub_by_arch`

```python
get_stub_by_arch(
    addr: int,
    size: int,
    perm: __main__.Permission
) → Union[str, bytearray, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChangePermissionCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChangePermissionCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ChecksecCommand`
Checksec the security properties of the current executable or passed as argument. The command checks for the following protections: 
- PIE 
- NX 
- RelRO 
- Glibc Stack Canaries 
- Fortify Source 

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ChecksecCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.print_security_properties"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.print_security_properties`

```python
print_security_properties(filename: str) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ChecksecCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ChecksecCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Color`
Used to colorify terminal output. 




---

<a href="https://cs.github.com/hugsy/gef?q=Color.blinkify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.blinkify`

```python
blinkify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.blueify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.blueify`

```python
blueify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.boldify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.boldify`

```python
boldify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.colorify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.colorify`

```python
colorify(text: str, attrs: str) → str
```

Color text according to the given attributes. 

---

<a href="https://cs.github.com/hugsy/gef?q=Color.cyanify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.cyanify`

```python
cyanify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.grayify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.grayify`

```python
grayify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.greenify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.greenify`

```python
greenify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.highlightify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.highlightify`

```python
highlightify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.light_grayify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.light_grayify`

```python
light_grayify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.pinkify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.pinkify`

```python
pinkify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.redify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.redify`

```python
redify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.underlinify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.underlinify`

```python
underlinify(msg: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=Color.yellowify"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Color.yellowify`

```python
yellowify(msg: str) → str
```






---

## <kbd>class</kbd> `ContextCommand`
Displays a comprehensive and modular summary of runtime context. Unless setting `enable` is set to False, this command will be spawned automatically every time GDB hits a breakpoint, a watchpoint, or any kind of interrupt. By default, it will show panes that contain the register states, the stack, and the disassembly code around $pc. 

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ContextCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.addr_has_breakpoint"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.addr_has_breakpoint`

```python
addr_has_breakpoint(address: int, bp_locations: List[str]) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_additional_information"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_additional_information`

```python
context_additional_information() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_args"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_args`

```python
context_args() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_code"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_code`

```python
context_code() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_memory"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_memory`

```python
context_memory() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_regs"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_regs`

```python
context_regs() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_source"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_source`

```python
context_source() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_stack"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_stack`

```python
context_stack() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_threads"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_threads`

```python
context_threads() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_title"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_title`

```python
context_title(m: Optional[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.context_trace"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.context_trace`

```python
context_trace() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.empty_extra_messages"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.empty_extra_messages`

```python
empty_extra_messages(_) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.get_pc_context_info"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.get_pc_context_info`

```python
get_pc_context_info(pc: int, line: str) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.line_has_breakpoint"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.line_has_breakpoint`

```python
line_has_breakpoint(
    file_name: str,
    line_number: int,
    bp_locations: List[str]
) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.print_arguments_from_symbol"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.print_arguments_from_symbol`

```python
print_arguments_from_symbol(function_name: str, symbol: 'gdb.Symbol') → None
```

If symbols were found, parse them and print the argument adequately. 

---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.print_guessed_arguments"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.print_guessed_arguments`

```python
print_guessed_arguments(function_name: str) → None
```

When no symbol, read the current basic block and look for "interesting" instructions. 

---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.show_legend"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.show_legend`

```python
show_legend() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.update_registers"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.update_registers`

```python
update_registers(_) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ContextCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ContextCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `DereferenceCommand`
Dereference recursively from an address and display information. This acts like WinDBG `dps` command. 

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> DereferenceCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.pprint_dereferenced"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.pprint_dereferenced`

```python
pprint_dereferenced(addr: int, idx: int, base_offset: int = 0) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=DereferenceCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DereferenceCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `DetailRegistersCommand`
Display full details on one, many or all registers value from current architecture. 

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> DetailRegistersCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=DetailRegistersCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `DetailRegistersCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Elf`
Basic ELF parsing. Ref: 
- http://www.skyfree.org/linux/references/ELF_Format.pdf 
- https://refspecs.linuxfoundation.org/elf/elfspec_ppc.pdf 
- https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html 

<a href="https://cs.github.com/hugsy/gef?q=Elf.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Elf.__init__`

```python
__init__(path: str = '', minimalist: bool = False) → None
```

Instantiate an ELF object. The default behavior is to create the object by parsing the ELF file. But in some cases (QEMU-stub), we may just want a simple minimal object with default values. 


---

#### <kbd>property</kbd> Elf.entry_point







---

<a href="https://cs.github.com/hugsy/gef?q=Elf.read"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Elf.read`

```python
read(size: int) → bytes
```





---

<a href="https://cs.github.com/hugsy/gef?q=Elf.read_and_unpack"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Elf.read_and_unpack`

```python
read_and_unpack(fmt: str) → Tuple[Any, ...]
```





---

<a href="https://cs.github.com/hugsy/gef?q=Elf.seek"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Elf.seek`

```python
seek(off: int) → None
```






---

## <kbd>class</kbd> `ElfInfoCommand`
Display a limited subset of ELF header information. If no argument is provided, the command will show information about the current ELF being debugged. 

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ElfInfoCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ElfInfoCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ElfInfoCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Endianness`
An enumeration. 





---

## <kbd>class</kbd> `EntryBreakBreakpoint`
Breakpoint used internally to stop execution at the most convenient entry point. 

<a href="https://cs.github.com/hugsy/gef?q=EntryBreakBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryBreakBreakpoint.__init__`

```python
__init__(location: str) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=EntryBreakBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryBreakBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `EntryPointBreakCommand`
Tries to find best entry point and sets a temporary breakpoint on it. The command will test for well-known symbols for entry points, such as `main`, `_main`, `__libc_start_main`, etc. defined by the setting `entrypoint_symbols`. 

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> EntryPointBreakCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.set_init_tbreak"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.set_init_tbreak`

```python
set_init_tbreak(addr: int) → EntryBreakBreakpoint
```





---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.set_init_tbreak_pie"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.set_init_tbreak_pie`

```python
set_init_tbreak_pie(addr: int, argv: List[str]) → EntryBreakBreakpoint
```





---

<a href="https://cs.github.com/hugsy/gef?q=EntryPointBreakCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `EntryPointBreakCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ExternalStructureManager`




<a href="https://cs.github.com/hugsy/gef?q=ExternalStructureManager.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ExternalStructureManager.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ExternalStructureManager.modules





---

#### <kbd>property</kbd> ExternalStructureManager.path





---

#### <kbd>property</kbd> ExternalStructureManager.structures






---

#### <kbd>handler</kbd> ExternalStructureManager.find


---

<a href="https://cs.github.com/hugsy/gef?q=ExternalStructureManager.clear_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ExternalStructureManager.clear_caches`

```python
clear_caches() → None
```






---

## <kbd>class</kbd> `FlagsCommand`
Edit flags in a human friendly way. 

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> FlagsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FlagsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FlagsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `FormatStringBreakpoint`
Inspect stack for format string. 

<a href="https://cs.github.com/hugsy/gef?q=FormatStringBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringBreakpoint.__init__`

```python
__init__(spec: str, num_args: int) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `FormatStringSearchCommand`
Exploitable format-string helper: this command will set up specific breakpoints at well-known dangerous functions (printf, snprintf, etc.), and check if the pointer holding the format string is writable, and therefore susceptible to format string attacks if an attacker can control its content. 

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> FormatStringSearchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=FormatStringSearchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FormatStringSearchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GdbRemoveReadlineFinder`







---

<a href="https://cs.github.com/hugsy/gef?q=GdbRemoveReadlineFinder.find_module"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GdbRemoveReadlineFinder.find_module`

```python
find_module(fullname, path=None)
```





---

<a href="https://cs.github.com/hugsy/gef?q=GdbRemoveReadlineFinder.load_module"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GdbRemoveReadlineFinder.load_module`

```python
load_module(fullname)
```






---

## <kbd>class</kbd> `Gef`
The GEF root class, which serves as a entrypoint for all the debugging session attributes (architecture, memory, settings, etc.). 

<a href="https://cs.github.com/hugsy/gef?q=Gef.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Gef.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=Gef.reinitialize_managers"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Gef.reinitialize_managers`

```python
reinitialize_managers() → None
```

Reinitialize the managers. Avoid calling this function directly, using `pi reset()` is preferred 

---

<a href="https://cs.github.com/hugsy/gef?q=Gef.reset_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Gef.reset_caches`

```python
reset_caches() → None
```

Recursively clean the cache of all the managers. Avoid calling this function directly, using `reset-cache` is preferred 

---

<a href="https://cs.github.com/hugsy/gef?q=Gef.setup"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Gef.setup`

```python
setup() → None
```

Setup initialize the runtime setup, which may require for the `gef` to be not None. 


---

## <kbd>class</kbd> `GefAlias`
Simple aliasing wrapper because GDB doesn't do what it should. 

<a href="https://cs.github.com/hugsy/gef?q=GefAlias.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefAlias.__init__`

```python
__init__(
    alias: str,
    command: str,
    completer_class: int = 0,
    command_class: int = -1
) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefAlias.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefAlias.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefAlias.lookup_command"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefAlias.lookup_command`

```python
lookup_command(cmd: str) → Union[Tuple[str, Type, Any], NoneType]
```






---

## <kbd>class</kbd> `GefCommand`
GEF main command: view all new commands by typing `gef`. 

<a href="https://cs.github.com/hugsy/gef?q=GefCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefCommand.loaded_command_names







---

<a href="https://cs.github.com/hugsy/gef?q=GefCommand.add_context_pane"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefCommand.add_context_pane`

```python
add_context_pane(
    pane_name: str,
    display_pane_function: Callable,
    pane_title_function: Callable
) → None
```

Add a new context pane to ContextCommand. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefCommand.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefCommand.load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefCommand.load`

```python
load(initial: bool = False) → None
```

Load all the commands and functions defined by GEF into GDB. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefCommand.setup"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefCommand.setup`

```python
setup() → None
```






---

## <kbd>class</kbd> `GefConfigCommand`
GEF configuration sub-command This command will help set/view GEF settings for the current debugging session. It is possible to make those changes permanent by running `gef save` (refer to this command help), and/or restore previously saved settings by running `gef restore` (refer help). 

<a href="https://cs.github.com/hugsy/gef?q=GefConfigCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefConfigCommand.__init__`

```python
__init__(loaded_commands: List[str]) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefConfigCommand.complete"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefConfigCommand.complete`

```python
complete(text: str, word: str) → List[str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefConfigCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefConfigCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefConfigCommand.print_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefConfigCommand.print_setting`

```python
print_setting(plugin_name: str, verbose: bool = False) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefConfigCommand.print_settings"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefConfigCommand.print_settings`

```python
print_settings() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefConfigCommand.set_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefConfigCommand.set_setting`

```python
set_setting(argv: Tuple[str, Any]) → None
```






---

## <kbd>class</kbd> `GefFunctionsCommand`
List the convenience functions provided by GEF. 

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefFunctionsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.add_function_to_doc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.add_function_to_doc`

```python
add_function_to_doc(function) → None
```

Add function to documentation. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.do_invoke`

```python
do_invoke(argv) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.setup"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.setup`

```python
setup() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefFunctionsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefFunctionsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GefHeapManager`
Class managing session heap. 

<a href="https://cs.github.com/hugsy/gef?q=GefHeapManager.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHeapManager.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefHeapManager.arenas





---

#### <kbd>property</kbd> GefHeapManager.base_address





---

#### <kbd>property</kbd> GefHeapManager.chunks





---

#### <kbd>property</kbd> GefHeapManager.main_arena





---

#### <kbd>property</kbd> GefHeapManager.selected_arena







---

<a href="https://cs.github.com/hugsy/gef?q=GefHeapManager.reset_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHeapManager.reset_caches`

```python
reset_caches() → None
```






---

## <kbd>class</kbd> `GefHelpCommand`
GEF help sub-command. 

<a href="https://cs.github.com/hugsy/gef?q=GefHelpCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHelpCommand.__init__`

```python
__init__(commands: List[Tuple[str, Any, Any]]) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefHelpCommand.add_command_to_doc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHelpCommand.add_command_to_doc`

```python
add_command_to_doc(
    command: Tuple[str, Type[__main__.GenericCommand], Any]
) → None
```

Add command to GEF documentation. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefHelpCommand.generate_help"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHelpCommand.generate_help`

```python
generate_help(
    commands: List[Tuple[str, Type[__main__.GenericCommand], Any]]
) → None
```

Generate builtin commands documentation. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefHelpCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHelpCommand.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefHelpCommand.refresh"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefHelpCommand.refresh`

```python
refresh() → None
```

Refresh the documentation. 


---

## <kbd>class</kbd> `GefManager`







---

<a href="https://cs.github.com/hugsy/gef?q=GefManager.reset_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefManager.reset_caches`

```python
reset_caches() → None
```

Reset the LRU-cached attributes 


---

## <kbd>class</kbd> `GefMemoryManager`
Class that manages memory access for gef. 

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefMemoryManager.maps







---

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.read"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.read`

```python
read(addr: int, length: int = 16) → bytes
```

Return a `length` long byte array with the copy of the process memory at `addr`. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.read_ascii_string"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.read_ascii_string`

```python
read_ascii_string(address: int) → Union[str, NoneType]
```

Read an ASCII string from memory 

---

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.read_cstring"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.read_cstring`

```python
read_cstring(
    address: int,
    max_length: int = 50,
    encoding: Optional[str] = None
) → str
```

Return a C-string read from memory. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.read_integer"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.read_integer`

```python
read_integer(addr: int) → int
```

Return an integer read from memory. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.reset_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.reset_caches`

```python
reset_caches() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefMemoryManager.write"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMemoryManager.write`

```python
write(address: int, buffer: ByteString, length: int = 16) → None
```

Write `buffer` at address `address`. 


---

## <kbd>class</kbd> `GefMissingCommand`
GEF missing sub-command Display the GEF commands that could not be loaded, along with the reason of why they could not be loaded. 

<a href="https://cs.github.com/hugsy/gef?q=GefMissingCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMissingCommand.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefMissingCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefMissingCommand.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```






---

## <kbd>class</kbd> `GefRestoreCommand`
GEF restore sub-command. Loads settings from file '~/.gef.rc' and apply them to the configuration of GEF. 

<a href="https://cs.github.com/hugsy/gef?q=GefRestoreCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefRestoreCommand.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefRestoreCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefRestoreCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```






---

## <kbd>class</kbd> `GefRunCommand`
Override GDB run commands with the context from GEF. Simple wrapper for GDB run command to use arguments set from `gef set args`. 

<a href="https://cs.github.com/hugsy/gef?q=GefRunCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefRunCommand.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefRunCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefRunCommand.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```






---

## <kbd>class</kbd> `GefSaveCommand`
GEF save sub-command. Saves the current configuration of GEF to disk (by default in file '~/.gef.rc'). 

<a href="https://cs.github.com/hugsy/gef?q=GefSaveCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSaveCommand.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefSaveCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSaveCommand.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```






---

## <kbd>class</kbd> `GefSessionManager`
Class managing the runtime properties of GEF.  

<a href="https://cs.github.com/hugsy/gef?q=GefSessionManager.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSessionManager.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefSessionManager.auxiliary_vector





---

#### <kbd>property</kbd> GefSessionManager.canary

Returns a tuple of the canary address and value, read from the auxiliary vector. 

---

#### <kbd>property</kbd> GefSessionManager.file

Return a Path object of the target process. 

---

#### <kbd>property</kbd> GefSessionManager.os

Return the current OS. 

---

#### <kbd>property</kbd> GefSessionManager.pagesize

Get the system page size 

---

#### <kbd>property</kbd> GefSessionManager.pid

Return the PID of the target process. 



---

<a href="https://cs.github.com/hugsy/gef?q=GefSessionManager.reset_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSessionManager.reset_caches`

```python
reset_caches() → None
```






---

## <kbd>class</kbd> `GefSetCommand`
Override GDB set commands with the context from GEF. 

<a href="https://cs.github.com/hugsy/gef?q=GefSetCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSetCommand.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefSetCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSetCommand.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```






---

## <kbd>class</kbd> `GefSetting`
Basic class for storing gef settings as objects 

<a href="https://cs.github.com/hugsy/gef?q=GefSetting.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSetting.__init__`

```python
__init__(
    value: Any,
    cls: Optional[type] = None,
    description: Optional[str] = None
) → None
```









---

## <kbd>class</kbd> `GefSettingsManager`
GefSettings acts as a dict where the global settings are stored and can be read, written or deleted as any other dict. For instance, to read a specific command setting: `gef.config[mycommand.mysetting]` 




---

<a href="https://cs.github.com/hugsy/gef?q=GefSettingsManager.raw_entry"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefSettingsManager.raw_entry`

```python
raw_entry(name: str) → GefSetting
```






---

## <kbd>class</kbd> `GefThemeCommand`
Customize GEF appearance. 

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefThemeCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.do_invoke`

```python
do_invoke(args: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefThemeCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefThemeCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GefTmuxSetup`
Setup a confortable tmux debugging environment. 

<a href="https://cs.github.com/hugsy/gef?q=GefTmuxSetup.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefTmuxSetup.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefTmuxSetup.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefTmuxSetup.invoke`

```python
invoke(args: Any, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GefTmuxSetup.screen_setup"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefTmuxSetup.screen_setup`

```python
screen_setup() → None
```

Hackish equivalent of the tmux_setup() function for screen. 

---

<a href="https://cs.github.com/hugsy/gef?q=GefTmuxSetup.tmux_setup"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefTmuxSetup.tmux_setup`

```python
tmux_setup() → None
```

Prepare the tmux environment by vertically splitting the current pane, and forcing the context to be redirected there. 


---

## <kbd>class</kbd> `GefUiManager`
Class managing UI settings. 

<a href="https://cs.github.com/hugsy/gef?q=GefUiManager.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefUiManager.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GefUiManager.reset_caches"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GefUiManager.reset_caches`

```python
reset_caches() → None
```

Reset the LRU-cached attributes 


---

## <kbd>class</kbd> `GenericArchitecture`





---

#### <kbd>property</kbd> GenericArchitecture.endianness





---

#### <kbd>property</kbd> GenericArchitecture.fp





---

#### <kbd>property</kbd> GenericArchitecture.pc





---

#### <kbd>property</kbd> GenericArchitecture.registers





---

#### <kbd>property</kbd> GenericArchitecture.sp







---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericArchitecture.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericArchitecture.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `GenericCommand`
This is an abstract class for invoking commands, should not be instantiated. 

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> GenericCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GenericFunction`
This is an abstract class for invoking convenience functions, should not be instantiated. 

<a href="https://cs.github.com/hugsy/gef?q=GenericFunction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericFunction.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GenericFunction.arg_to_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericFunction.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GenericFunction.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GenericFunction.invoke`

```python
invoke(*args: Any) → int
```






---

## <kbd>class</kbd> `GlibcArena`
Glibc arena class Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671 

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.__init__`

```python
__init__(addr: str) → None
```






---

#### <kbd>property</kbd> GlibcArena.addr







---

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.bin"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.bin`

```python
bin(i: int) → Tuple[int, int]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.fastbin"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.fastbin`

```python
fastbin(i: int) → Union[ForwardRef('GlibcChunk'), NoneType]
```

Return head chunk in fastbinsY[i]. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.get_heap_for_ptr"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.get_heap_for_ptr`

```python
get_heap_for_ptr(ptr: int) → int
```

Find the corresponding heap for a given pointer (int). See https://github.com/bminor/glibc/blob/glibc-2.34/malloc/arena.c#L129 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.get_heap_info_list"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.get_heap_info_list`

```python
get_heap_info_list() → Union[List[__main__.GlibcHeapInfo], NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.heap_addr"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.heap_addr`

```python
heap_addr(allow_unaligned: bool = False) → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcArena.is_main_arena"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcArena.is_main_arena`

```python
is_main_arena() → bool
```






---

## <kbd>class</kbd> `GlibcChunk`
Glibc chunk class. The default behavior (from_base=False) is to interpret the data starting at the memory address pointed to as the chunk data. Setting from_base to True instead treats that data as the chunk header. Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.__init__`

```python
__init__(
    addr: int,
    from_base: bool = False,
    allow_unaligned: bool = True
) → None
```






---

#### <kbd>property</kbd> GlibcChunk.bck





---

#### <kbd>property</kbd> GlibcChunk.bk





---

#### <kbd>property</kbd> GlibcChunk.fd





---

#### <kbd>property</kbd> GlibcChunk.fwd





---

#### <kbd>property</kbd> GlibcChunk.size





---

#### <kbd>property</kbd> GlibcChunk.usable_size







---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.flags_as_string"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.flags_as_string`

```python
flags_as_string() → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_bkw_ptr"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_bkw_ptr`

```python
get_bkw_ptr() → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_chunk_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_chunk_size`

```python
get_chunk_size() → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_fwd_ptr"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_fwd_ptr`

```python
get_fwd_ptr(sll: bool) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_next_chunk"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_next_chunk`

```python
get_next_chunk(allow_unaligned: bool = False) → GlibcChunk
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_next_chunk_addr"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_next_chunk_addr`

```python
get_next_chunk_addr() → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_prev_chunk_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_prev_chunk_size`

```python
get_prev_chunk_size() → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.get_usable_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.get_usable_size`

```python
get_usable_size() → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.has_m_bit"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.has_m_bit`

```python
has_m_bit() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.has_n_bit"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.has_n_bit`

```python
has_n_bit() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.has_p_bit"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.has_p_bit`

```python
has_p_bit() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.is_used"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.is_used`

```python
is_used() → bool
```

Check if the current block is used by: 
- checking the M bit is true 
- or checking that next chunk PREV_INUSE flag is true 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.psprint"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.psprint`

```python
psprint() → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.str_as_alloced"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.str_as_alloced`

```python
str_as_alloced() → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.str_as_freed"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.str_as_freed`

```python
str_as_freed() → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcChunk.str_chunk_size_flag"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcChunk.str_chunk_size_flag`

```python
str_chunk_size_flag() → str
```






---

## <kbd>class</kbd> `GlibcHeapArenaCommand`
Display information on a heap chunk. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> GlibcHeapArenaCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapArenaCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapArenaCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapBinsCommand`
Display information on the bins on an arena (default: main_arena). See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.pprint_bin"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.pprint_bin`

```python
pprint_bin(arena_addr: str, index: int, _type: str = '') → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapBinsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapChunkCommand`
Display information on a heap chunk. See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapChunkCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunkCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunkCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapChunksCommand`
Display all heap chunks for the current arena. As an optional argument the base address of a different arena can be passed 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapChunksCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.dump_chunks_arena"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.dump_chunks_arena`

```python
dump_chunks_arena(
    arena: __main__.GlibcArena,
    print_arena: bool = False,
    allow_unaligned: bool = False
) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.dump_chunks_heap"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.dump_chunks_heap`

```python
dump_chunks_heap(
    start: int,
    until: Optional[int] = None,
    top: Optional[int] = None,
    allow_unaligned: bool = False
) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapChunksCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapChunksCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapCommand`
Base command to get information about the Glibc heap structure. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapFastbinsYCommand`
Display information on the fastbinsY on an arena (default: main_arena). See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapFastbinsYCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapFastbinsYCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapFastbinsYCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapInfo`
Glibc heap_info struct See https://github.com/bminor/glibc/blob/glibc-2.34/malloc/arena.c#L64 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapInfo.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapInfo.__init__`

```python
__init__(addr: Union[int, str]) → None
```






---

#### <kbd>property</kbd> GlibcHeapInfo.addr





---

#### <kbd>property</kbd> GlibcHeapInfo.ar_ptr





---

#### <kbd>property</kbd> GlibcHeapInfo.ar_ptr_addr





---

#### <kbd>property</kbd> GlibcHeapInfo.mprotect_size





---

#### <kbd>property</kbd> GlibcHeapInfo.mprotect_size_addr





---

#### <kbd>property</kbd> GlibcHeapInfo.prev





---

#### <kbd>property</kbd> GlibcHeapInfo.prev_addr





---

#### <kbd>property</kbd> GlibcHeapInfo.size





---

#### <kbd>property</kbd> GlibcHeapInfo.size_addr








---

## <kbd>class</kbd> `GlibcHeapLargeBinsCommand`
Convenience command for viewing large bins. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapLargeBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapLargeBinsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapLargeBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapSetArenaCommand`
Display information on a heap chunk. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapSetArenaCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSetArenaCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSetArenaCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapSmallBinsCommand`
Convenience command for viewing small bins. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapSmallBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapSmallBinsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapSmallBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapTcachebinsCommand`
Display information on the Tcachebins on an arena (default: main_arena). See https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapTcachebinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.check_thread_ids"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.check_thread_ids`

```python
check_thread_ids(tids: List[int]) → List[int]
```

Check the validity, dedup, and return all valid tids. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.find_tcache"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.find_tcache`

```python
find_tcache() → int
```

Return the location of the current thread's tcache. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.tcachebin"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.tcachebin`

```python
tcachebin(
    tcache_base: int,
    i: int
) → Tuple[Union[__main__.GlibcChunk, NoneType], int]
```

Return the head chunk in tcache[i] and the number of chunks in the bin. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapTcachebinsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapTcachebinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapUnsortedBinsCommand`
Display information on the Unsorted Bins of an arena (default: main_arena). See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689. 

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapUnsortedBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GlibcHeapUnsortedBinsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GlibcHeapUnsortedBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GotBaseFunction`
Return the current GOT base address plus the given offset. 

<a href="https://cs.github.com/hugsy/gef?q=GotBaseFunction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=GotBaseFunction.arg_to_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotBaseFunction.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotBaseFunction.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotBaseFunction.invoke`

```python
invoke(*args: Any) → int
```






---

## <kbd>class</kbd> `GotCommand`
Display current status of the got inside the process. 

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.__init__`

```python
__init__()
```






---

#### <kbd>property</kbd> GotCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.get_jmp_slots"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.get_jmp_slots`

```python
get_jmp_slots(readelf: str, filename: str) → List[str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=GotCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `GotCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HeapAnalysisCommand`
Heap vulnerability analysis helper: this command aims to track dynamic heap allocation done through malloc()/free() to provide some insights on possible heap vulnerabilities. The following vulnerabilities are checked: 
- NULL free 
- Use-after-Free 
- Double Free 
- Heap overlap 

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HeapAnalysisCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.clean"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.clean`

```python
clean(_: 'gdb.Event') → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.dump_tracked_allocations"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.dump_tracked_allocations`

```python
dump_tracked_allocations() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.setup"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.setup`

```python
setup() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapAnalysisCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapAnalysisCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HeapBaseFunction`
Return the current heap base address plus an optional offset. 

<a href="https://cs.github.com/hugsy/gef?q=HeapBaseFunction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=HeapBaseFunction.arg_to_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapBaseFunction.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=HeapBaseFunction.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HeapBaseFunction.invoke`

```python
invoke(*args: Any) → int
```






---

## <kbd>class</kbd> `HexdumpByteCommand`
Display SIZE lines of hexdump as BYTE from the memory location pointed by ADDRESS. 

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpByteCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpByteCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpByteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpCommand`
Display SIZE lines of hexdump from the memory location pointed by LOCATION. 

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpDwordCommand`
Display SIZE lines of hexdump as DWORD from the memory location pointed by ADDRESS. 

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpDwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpDwordCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpDwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpQwordCommand`
Display SIZE lines of hexdump as QWORD from the memory location pointed by ADDRESS. 

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpQwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpQwordCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpQwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpWordCommand`
Display SIZE lines of hexdump as WORD from the memory location pointed by ADDRESS. 

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpWordCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HexdumpWordCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HexdumpWordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightAddCommand`
Add a match to the highlight table. 

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> HighlightAddCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightAddCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightAddCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightClearCommand`
Clear the highlight table, remove all matches. 

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> HighlightClearCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightClearCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightClearCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightCommand`
Highlight user-defined text matches in GEF output universally. 

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HighlightCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightListCommand`
Show the current highlight table with matches to colors. 

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> HighlightListCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.print_highlight_table"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.print_highlight_table`

```python
print_highlight_table() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightListCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightRemoveCommand`
Remove a match in the highlight table. 

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> HighlightRemoveCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=HighlightRemoveCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `HighlightRemoveCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `IdaInteractCommand`
IDA Interact: set of commands to interact with IDA via a XML RPC service deployed via the IDA script `ida_gef.py`. It should be noted that this command can also be used to interact with Binary Ninja (using the script `binja_gef.py`) using the same interface. 

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> IdaInteractCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.connect"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.connect`

```python
connect(host: Optional[str] = None, port: Optional[int] = None) → None
```

Connect to the XML-RPC service. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.disconnect"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.disconnect`

```python
disconnect() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```

`do_invoke` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.import_structures"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.import_structures`

```python
import_structures(structs: Dict[str, List[Tuple[int, str, int]]]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.is_target_alive"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.is_target_alive`

```python
is_target_alive(host: str, port: int) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.synchronize"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.synchronize`

```python
synchronize() → None
```

Submit all active breakpoint addresses to IDA/BN. 

---

<a href="https://cs.github.com/hugsy/gef?q=IdaInteractCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IdaInteractCommand.usage`

```python
usage(meth: Optional[str] = None) → None
```






---

## <kbd>class</kbd> `Instruction`
GEF representation of a CPU instruction. 

<a href="https://cs.github.com/hugsy/gef?q=Instruction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Instruction.__init__`

```python
__init__(
    address: int,
    location: str,
    mnemo: str,
    operands: List[str],
    opcodes: bytearray
) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=Instruction.is_valid"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Instruction.is_valid`

```python
is_valid() → bool
```






---

## <kbd>class</kbd> `IsSyscallCommand`
Tells whether the next instruction is a system call. 

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> IsSyscallCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.is_syscall"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.is_syscall`

```python
is_syscall(
    arch: __main__.Architecture,
    instruction: __main__.Instruction
) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=IsSyscallCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `IsSyscallCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MIPS`





---

#### <kbd>property</kbd> MIPS.endianness





---

#### <kbd>property</kbd> MIPS.fp





---

#### <kbd>property</kbd> MIPS.pc





---

#### <kbd>property</kbd> MIPS.registers





---

#### <kbd>property</kbd> MIPS.sp







---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `MIPS64`





---

#### <kbd>property</kbd> MIPS64.endianness





---

#### <kbd>property</kbd> MIPS64.fp





---

#### <kbd>property</kbd> MIPS64.pc





---

#### <kbd>property</kbd> MIPS64.registers





---

#### <kbd>property</kbd> MIPS64.sp







---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=MIPS64.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MIPS64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `MallocStateStruct`
GEF representation of malloc_state from https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c#L1658 

<a href="https://cs.github.com/hugsy/gef?q=MallocStateStruct.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MallocStateStruct.__init__`

```python
__init__(addr: str) → None
```






---

#### <kbd>property</kbd> MallocStateStruct.addr





---

#### <kbd>property</kbd> MallocStateStruct.bins





---

#### <kbd>property</kbd> MallocStateStruct.bins_addr





---

#### <kbd>property</kbd> MallocStateStruct.fastbinsY





---

#### <kbd>property</kbd> MallocStateStruct.fastbins_addr





---

#### <kbd>property</kbd> MallocStateStruct.last_remainder





---

#### <kbd>property</kbd> MallocStateStruct.last_remainder_addr





---

#### <kbd>property</kbd> MallocStateStruct.next





---

#### <kbd>property</kbd> MallocStateStruct.next_addr





---

#### <kbd>property</kbd> MallocStateStruct.next_free





---

#### <kbd>property</kbd> MallocStateStruct.next_free_addr





---

#### <kbd>property</kbd> MallocStateStruct.struct_size





---

#### <kbd>property</kbd> MallocStateStruct.system_mem





---

#### <kbd>property</kbd> MallocStateStruct.system_mem_addr





---

#### <kbd>property</kbd> MallocStateStruct.top





---

#### <kbd>property</kbd> MallocStateStruct.top_addr







---

<a href="https://cs.github.com/hugsy/gef?q=MallocStateStruct.get_size_t"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MallocStateStruct.get_size_t`

```python
get_size_t(addr: int) → gdb.Value
```





---

<a href="https://cs.github.com/hugsy/gef?q=MallocStateStruct.get_size_t_array"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MallocStateStruct.get_size_t_array`

```python
get_size_t_array(addr: int, length: int) → gdb.Value
```





---

<a href="https://cs.github.com/hugsy/gef?q=MallocStateStruct.get_size_t_pointer"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MallocStateStruct.get_size_t_pointer`

```python
get_size_t_pointer(addr: int) → gdb.Value
```






---

## <kbd>class</kbd> `MemoryCommand`
Add or remove address ranges to the memory view. 

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> MemoryCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryUnwatchCommand`
Removes address ranges to the memory view. 

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> MemoryUnwatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryUnwatchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryUnwatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryWatchCommand`
Adds address ranges to the memory view. 

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> MemoryWatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryWatchListCommand`
Lists all watchpoints to display in context layout. 

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> MemoryWatchListCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchListCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryWatchResetCommand`
Removes all watchpoints. 

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> MemoryWatchResetCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=MemoryWatchResetCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `MemoryWatchResetCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `NamedBreakpoint`
Breakpoint which shows a specified name, when hit. 

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpoint.__init__`

```python
__init__(location: str, name: str) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `NamedBreakpointCommand`
Sets a breakpoint and assigns a name to it, which will be shown, when it's hit. 

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> NamedBreakpointCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NamedBreakpointCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NamedBreakpointCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `NopCommand`
Patch the instruction(s) pointed by parameters with NOP. Note: this command is architecture aware. 

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> NopCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.get_insn_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.get_insn_size`

```python
get_insn_size(addr: int) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.nop_bytes"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.nop_bytes`

```python
nop_bytes(loc: int, num_bytes: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=NopCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `NopCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomCommand`
Dump user defined structure. This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows to apply structures (from symbols or custom) directly to an address. Custom structures can be defined in pure Python using ctypes, and should be stored in a specific directory, whose path must be stored in the `pcustom.struct_path` configuration setting. 

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.explode_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.explode_type`

```python
explode_type(arg: str) → Tuple[str, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomEditCommand`
PCustom: edit the content of a given structure 

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomEditCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.explode_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.explode_type`

```python
explode_type(arg: str) → Tuple[str, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomEditCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomEditCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomListCommand`
PCustom: list available structures 

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomListCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.do_invoke`

```python
do_invoke(_: List) → None
```

Dump the list of all the structures and their respective. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.explode_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.explode_type`

```python
explode_type(arg: str) → Tuple[str, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomListCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomShowCommand`
PCustom: show the content of a given structure 

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomShowCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.explode_type"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.explode_type`

```python
explode_type(arg: str) → Tuple[str, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PCustomShowCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PCustomShowCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchByteCommand`
Write specified WORD to the specified address. 

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchByteCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchByteCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchByteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchCommand`
Write specified values to the specified address. 

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchDwordCommand`
Write specified DWORD to the specified address. 

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchDwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchDwordCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchDwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchQwordCommand`
Write specified QWORD to the specified address. 

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchQwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchQwordCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchQwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchStringCommand`
Write specified string to the specified memory location pointed by ADDRESS. 

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PatchStringCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchStringCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchStringCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchWordCommand`
Write specified WORD to the specified address. 

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchWordCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatchWordCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatchWordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatternCommand`
Generate or Search a De Bruijn Sequence of unique substrings of length N and a total length of LENGTH. The default value of N is set to match the currently loaded architecture. 

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatternCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatternCreateCommand`
Generate a De Bruijn Sequence of unique substrings of length N and a total length of LENGTH. The default value of N is set to match the currently loaded architecture. 

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PatternCreateCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternCreateCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternCreateCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatternSearchCommand`
Search a De Bruijn Sequence of unique substrings of length N and a maximum total length of MAX_LENGTH. The default value of N is set to match the currently loaded architecture. The PATTERN argument can be a GDB symbol (such as a register name), a string or a hexadecimal value 

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PatternSearchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.search"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.search`

```python
search(pattern: str, size: int, period: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PatternSearchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PatternSearchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Permission`
GEF representation of Linux permission. 





---

## <kbd>class</kbd> `Phdr`




<a href="https://cs.github.com/hugsy/gef?q=Phdr.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Phdr.__init__`

```python
__init__(elf: __main__.Elf, off: int) → None
```









---

## <kbd>class</kbd> `PieAttachCommand`
Do attach with PIE breakpoint support. 

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PieAttachCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieAttachCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieAttachCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieBreakpointCommand`
Set a PIE breakpoint at an offset from the target binaries base address. 

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PieBreakpointCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.set_pie_breakpoint"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.set_pie_breakpoint`

```python
set_pie_breakpoint(set_func: Callable[[int], str], addr: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieBreakpointCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieBreakpointCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieCommand`
PIE breakpoint support. 

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PieCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieDeleteCommand`
Delete a PIE breakpoint. 

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PieDeleteCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.delete_bp"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.delete_bp`

```python
delete_bp(breakpoints: List) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieDeleteCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieDeleteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieInfoCommand`
Display breakpoint info. 

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PieInfoCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieInfoCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieInfoCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieRemoteCommand`
Attach to a remote connection with PIE breakpoint support. 

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PieRemoteCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRemoteCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRemoteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieRunCommand`
Run process with PIE breakpoint support. 

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> PieRunCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieRunCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieRunCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieVirtualBreakpoint`
PIE virtual breakpoint (not real breakpoint). 

<a href="https://cs.github.com/hugsy/gef?q=PieVirtualBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieVirtualBreakpoint.__init__`

```python
__init__(set_func: Callable[[int], str], vbp_num: int, addr: int) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=PieVirtualBreakpoint.destroy"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieVirtualBreakpoint.destroy`

```python
destroy() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PieVirtualBreakpoint.instantiate"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PieVirtualBreakpoint.instantiate`

```python
instantiate(base: int) → None
```






---

## <kbd>class</kbd> `PowerPC`





---

#### <kbd>property</kbd> PowerPC.endianness





---

#### <kbd>property</kbd> PowerPC.fp





---

#### <kbd>property</kbd> PowerPC.pc





---

#### <kbd>property</kbd> PowerPC.ptrsize





---

#### <kbd>property</kbd> PowerPC.registers





---

#### <kbd>property</kbd> PowerPC.sp







---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `PowerPC64`





---

#### <kbd>property</kbd> PowerPC64.endianness





---

#### <kbd>property</kbd> PowerPC64.fp





---

#### <kbd>property</kbd> PowerPC64.pc





---

#### <kbd>property</kbd> PowerPC64.ptrsize





---

#### <kbd>property</kbd> PowerPC64.registers





---

#### <kbd>property</kbd> PowerPC64.sp







---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=PowerPC64.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PowerPC64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `PrintFormatCommand`
Print bytes format in commonly used formats, such as literals in high level languages. 

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PrintFormatCommand.format_matrix





---

#### <kbd>property</kbd> PrintFormatCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=PrintFormatCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `PrintFormatCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ProcessListingCommand`
List and filter process. If a PATTERN is given as argument, results shown will be grepped by this pattern. 

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ProcessListingCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.get_processes"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.get_processes`

```python
get_processes() → Generator[Dict[str, str], NoneType, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessListingCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessListingCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ProcessStatusCommand`
Extends the info given by GDB `info proc`, by giving an exhaustive description of the process status (file descriptors, ancestor, descendants, etc.). 

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ProcessStatusCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.get_children_pids"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.get_children_pids`

```python
get_children_pids(pid: int) → List[int]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.get_cmdline_of"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.get_cmdline_of`

```python
get_cmdline_of(pid: int) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.get_process_path_of"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.get_process_path_of`

```python
get_process_path_of(pid: int) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.get_state_of"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.get_state_of`

```python
get_state_of(pid: int) → Dict[str, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.list_sockets"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.list_sockets`

```python
list_sockets(pid: int) → List[int]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.parse_ip_port"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.parse_ip_port`

```python
parse_ip_port(addr: str) → Tuple[str, int]
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.show_ancestor"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.show_ancestor`

```python
show_ancestor() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.show_connections"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.show_connections`

```python
show_connections() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.show_descendants"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.show_descendants`

```python
show_descendants() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.show_fds"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.show_fds`

```python
show_fds() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.show_info_proc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.show_info_proc`

```python
show_info_proc() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ProcessStatusCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ProcessStatusCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `RISCV`





---

#### <kbd>property</kbd> RISCV.endianness





---

#### <kbd>property</kbd> RISCV.fp





---

#### <kbd>property</kbd> RISCV.instruction_length





---

#### <kbd>property</kbd> RISCV.pc





---

#### <kbd>property</kbd> RISCV.ptrsize





---

#### <kbd>property</kbd> RISCV.registers





---

#### <kbd>property</kbd> RISCV.sp







---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=RISCV.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RISCV.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `RedirectOutputContext`




<a href="https://cs.github.com/hugsy/gef?q=RedirectOutputContext.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RedirectOutputContext.__init__`

```python
__init__(to: str = '/dev/null') → None
```









---

## <kbd>class</kbd> `RemoteCommand`
gef wrapper for the `target remote` command. This command will automatically download the target binary in the local temporary directory (defaut /tmp) and then source it. Additionally, it will fetch all the /proc/PID/maps and loads all its information. 

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> RemoteCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.connect_target"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.connect_target`

```python
connect_target(target: str, is_extended_remote: bool) → bool
```

Connect to remote target and get symbols. To prevent `gef` from requesting information not fetched just yet, we disable the context disable when connection was successful. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.load_from_remote_proc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.load_from_remote_proc`

```python
load_from_remote_proc(pid: int, info: str) → Union[str, NoneType]
```

Download one item from /proc/pid. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.new_objfile_handler"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.new_objfile_handler`

```python
new_objfile_handler(event: 'gdb.Event') → None
```

Hook that handles new_objfile events, will update remote environment accordingly. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.prepare_qemu_stub"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.prepare_qemu_stub`

```python
prepare_qemu_stub(target: str) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.refresh_shared_library_path"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.refresh_shared_library_path`

```python
refresh_shared_library_path() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.setup_remote_environment"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.setup_remote_environment`

```python
setup_remote_environment(pid: int, update_solib: bool = False) → None
```

Clone the remote environment locally in the temporary directory. The command will duplicate the entries in the /proc/<pid> locally and then source those information into the current gdb context to allow gef to use all the extra commands as it was local debugging. 

---

<a href="https://cs.github.com/hugsy/gef?q=RemoteCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RemoteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ResetCacheCommand`
Reset cache of all stored data. This command is here for debugging and test purposes, GEF handles properly the cache reset under "normal" scenario. 

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> ResetCacheCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ResetCacheCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ResetCacheCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `RopperCommand`
Ropper (https://scoding.de/ropper/) plugin. 

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> RopperCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=RopperCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `RopperCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SPARC`
Refs: 
- https://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf 


---

#### <kbd>property</kbd> SPARC.endianness





---

#### <kbd>property</kbd> SPARC.fp





---

#### <kbd>property</kbd> SPARC.pc





---

#### <kbd>property</kbd> SPARC.ptrsize





---

#### <kbd>property</kbd> SPARC.registers





---

#### <kbd>property</kbd> SPARC.sp







---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `SPARC64`
Refs: 
- http://math-atlas.sourceforge.net/devel/assembly/abi_sysV_sparc.pdf 
- https://cr.yp.to/2005-590/sparcv9.pdf 


---

#### <kbd>property</kbd> SPARC64.endianness





---

#### <kbd>property</kbd> SPARC64.fp





---

#### <kbd>property</kbd> SPARC64.pc





---

#### <kbd>property</kbd> SPARC64.ptrsize





---

#### <kbd>property</kbd> SPARC64.registers





---

#### <kbd>property</kbd> SPARC64.sp







---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=SPARC64.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SPARC64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `ScanSectionCommand`
Search for addresses that are located in a memory mapping (haystack) that belonging to another (needle). 

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> ScanSectionCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ScanSectionCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ScanSectionCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SearchPatternCommand`
SearchPatternCommand: search a pattern in memory. If given an hex value (starting with 0x) the command will also try to look for upwards cross-references to this address. 

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> SearchPatternCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.print_loc"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.print_loc`

```python
print_loc(loc: Tuple[int, int, str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.print_section"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.print_section`

```python
print_section(section: __main__.Section) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.search_pattern"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.search_pattern`

```python
search_pattern(pattern: str, section_name: str) → None
```

Search a pattern within the whole userland memory. 

---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.search_pattern_by_address"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.search_pattern_by_address`

```python
search_pattern_by_address(
    pattern: str,
    start_address: int,
    end_address: int
) → List[Tuple[int, int, Union[str, NoneType]]]
```

Search a pattern within a range defined by arguments. 

---

<a href="https://cs.github.com/hugsy/gef?q=SearchPatternCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SearchPatternCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Section`
GEF representation of process memory sections. 

<a href="https://cs.github.com/hugsy/gef?q=Section.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Section.__init__`

```python
__init__(**kwargs: Any) → None
```






---

#### <kbd>property</kbd> Section.realpath





---

#### <kbd>property</kbd> Section.size







---

<a href="https://cs.github.com/hugsy/gef?q=Section.is_executable"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Section.is_executable`

```python
is_executable() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Section.is_readable"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Section.is_readable`

```python
is_readable() → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=Section.is_writable"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Section.is_writable`

```python
is_writable() → bool
```






---

## <kbd>class</kbd> `SectionBaseFunction`
Return the matching file's base address plus an optional offset. Defaults to current file. Note that quotes need to be escaped 

<a href="https://cs.github.com/hugsy/gef?q=SectionBaseFunction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SectionBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=SectionBaseFunction.arg_to_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SectionBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=SectionBaseFunction.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SectionBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=SectionBaseFunction.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SectionBaseFunction.invoke`

```python
invoke(*args: Any) → int
```






---

## <kbd>class</kbd> `Shdr`




<a href="https://cs.github.com/hugsy/gef?q=Shdr.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `Shdr.__init__`

```python
__init__(elf: Optional[__main__.Elf], off: int) → None
```









---

## <kbd>class</kbd> `ShellcodeCommand`
ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to download shellcodes. 

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ShellcodeCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ShellcodeGetCommand`
Download shellcode from shell-storm's shellcode database. 

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> ShellcodeGetCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.get_shellcode"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.get_shellcode`

```python
get_shellcode(sid: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeGetCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeGetCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ShellcodeSearchCommand`
Search pattern in shell-storm's shellcode database. 

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> ShellcodeSearchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.search_shellcode"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.search_shellcode`

```python
search_shellcode(search_options: List) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=ShellcodeSearchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ShellcodeSearchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SmartEvalCommand`
SmartEval: Smart eval (vague approach to mimic WinDBG `?`). 

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> SmartEvalCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.distance"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.distance`

```python
distance(args: Tuple[str, str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.evaluate"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.evaluate`

```python
evaluate(expr: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SmartEvalCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SmartEvalCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SolveKernelSymbolCommand`
Solve kernel symbols from kallsyms table. 

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> SolveKernelSymbolCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SolveKernelSymbolCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SolveKernelSymbolCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `StackOffsetFunction`
Return the current stack base address plus an optional offset. 

<a href="https://cs.github.com/hugsy/gef?q=StackOffsetFunction.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StackOffsetFunction.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=StackOffsetFunction.arg_to_long"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StackOffsetFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=StackOffsetFunction.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StackOffsetFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=StackOffsetFunction.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StackOffsetFunction.invoke`

```python
invoke(*args: Any) → int
```






---

## <kbd>class</kbd> `StubBreakpoint`
Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.). 

<a href="https://cs.github.com/hugsy/gef?q=StubBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubBreakpoint.__init__`

```python
__init__(func: str, retval: Optional[int]) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=StubBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `StubCommand`
Stub out the specified function. This function is useful when needing to skip one function to be called and disrupt your runtime flow (ex. fork). 

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> StubCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=StubCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `StubCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SyscallArgsCommand`
Gets the syscall name and arguments based on the register values in the current state. 

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> SyscallArgsCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.get_filepath"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.get_filepath`

```python
get_filepath(x: str) → Union[pathlib.Path, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.get_module"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.get_module`

```python
get_module(modname: str) → Any
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.get_settings_path"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.get_settings_path`

```python
get_settings_path() → Union[pathlib.Path, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.get_syscall_table"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.get_syscall_table`

```python
get_syscall_table(modname: str) → Dict[str, Any]
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=SyscallArgsCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `SyscallArgsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `TraceFreeBreakpoint`
Track calls to free() and attempts to detect inconsistencies. 

<a href="https://cs.github.com/hugsy/gef?q=TraceFreeBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceFreeBreakpoint.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=TraceFreeBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceFreeBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceFreeRetBreakpoint`
Internal temporary breakpoint to track free()d values. 

<a href="https://cs.github.com/hugsy/gef?q=TraceFreeRetBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceFreeRetBreakpoint.__init__`

```python
__init__(addr: int) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=TraceFreeRetBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceFreeRetBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceMallocBreakpoint`
Track allocations done with malloc() or calloc(). 

<a href="https://cs.github.com/hugsy/gef?q=TraceMallocBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceMallocBreakpoint.__init__`

```python
__init__(name: str) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=TraceMallocBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceMallocBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceMallocRetBreakpoint`
Internal temporary breakpoint to retrieve the return value of malloc(). 

<a href="https://cs.github.com/hugsy/gef?q=TraceMallocRetBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceMallocRetBreakpoint.__init__`

```python
__init__(size: int, name: str) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=TraceMallocRetBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceMallocRetBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceReallocBreakpoint`
Track re-allocations done with realloc(). 

<a href="https://cs.github.com/hugsy/gef?q=TraceReallocBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceReallocBreakpoint.__init__`

```python
__init__() → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=TraceReallocBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceReallocBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceReallocRetBreakpoint`
Internal temporary breakpoint to retrieve the return value of realloc(). 

<a href="https://cs.github.com/hugsy/gef?q=TraceReallocRetBreakpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceReallocRetBreakpoint.__init__`

```python
__init__(ptr: int, size: int) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=TraceReallocRetBreakpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceReallocRetBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceRunCommand`
Create a runtime trace of all instructions executed from $pc to LOCATION specified. The trace is stored in a text file that can be next imported in IDA Pro to visualize the runtime path. 

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> TraceRunCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.get_frames_size"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.get_frames_size`

```python
get_frames_size() → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.start_tracing"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.start_tracing`

```python
start_tracing(loc_start: int, loc_end: int, depth: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.trace"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.trace`

```python
trace(loc_start: int, loc_end: int, depth: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=TraceRunCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `TraceRunCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `UafWatchpoint`
Custom watchpoints set TraceFreeBreakpoint() to monitor free()d pointers being used. 

<a href="https://cs.github.com/hugsy/gef?q=UafWatchpoint.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UafWatchpoint.__init__`

```python
__init__(addr: int) → None
```








---

<a href="https://cs.github.com/hugsy/gef?q=UafWatchpoint.stop"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UafWatchpoint.stop`

```python
stop() → bool
```

If this method is triggered, we likely have a UaF. Break the execution and report it. 


---

## <kbd>class</kbd> `UnicornEmulateCommand`
Use Unicorn-Engine to emulate the behavior of the binary, without affecting the GDB runtime. By default the command will emulate only the next instruction, but location and number of instruction can be changed via arguments to the command line. By default, it will emulate the next instruction from current PC. 

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> UnicornEmulateCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.wrapper"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.wrapper`

```python
wrapper(*args: Any, **kwargs: Any) → Union[Callable, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.get_unicorn_end_addr"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.get_unicorn_end_addr`

```python
get_unicorn_end_addr(start_addr: int, nb: int) → int
```





---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.run_unicorn"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.run_unicorn`

```python
run_unicorn(start_insn_addr: int, end_insn_addr: int, **kwargs: Any) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=UnicornEmulateCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `UnicornEmulateCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `VMMapCommand`
Display a comprehensive layout of the virtual memory mapping. If a filter argument, GEF will filter out the mapping whose pathname do not match that filter. 

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> VMMapCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.is_integer"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.is_integer`

```python
is_integer(n: str) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.print_entry"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.print_entry`

```python
print_entry(entry: __main__.Section) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.show_legend"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.show_legend`

```python
show_legend() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VMMapCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VMMapCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `VersionCommand`
Display GEF version info. 

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> VersionCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=VersionCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `VersionCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `X86`





---

#### <kbd>property</kbd> X86.fp





---

#### <kbd>property</kbd> X86.pc





---

#### <kbd>property</kbd> X86.registers





---

#### <kbd>property</kbd> X86.sp







---

<a href="https://cs.github.com/hugsy/gef?q=X86.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `X86_64`





---

#### <kbd>property</kbd> X86_64.fp





---

#### <kbd>property</kbd> X86_64.pc





---

#### <kbd>property</kbd> X86_64.registers





---

#### <kbd>property</kbd> X86_64.sp







---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.flag_register_to_human"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.get_ith_parameter"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.get_ra"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.get_ra`

```python
get_ra(insn: __main__.Instruction, frame: 'gdb.Frame') → Union[int, NoneType]
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.is_branch_taken"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.is_branch_taken`

```python
is_branch_taken(insn: __main__.Instruction) → Tuple[bool, str]
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.is_call"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.is_call`

```python
is_call(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.is_conditional_branch"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.is_conditional_branch`

```python
is_conditional_branch(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.is_ret"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.is_ret`

```python
is_ret(insn: __main__.Instruction) → bool
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.mprotect_asm"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm: __main__.Permission) → str
```





---

<a href="https://cs.github.com/hugsy/gef?q=X86_64.register"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `X86_64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `XAddressInfoCommand`
Retrieve and display runtime information for the location(s) given as parameter. 

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> XAddressInfoCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.infos"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.infos`

```python
infos(address: int) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XAddressInfoCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XAddressInfoCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XFilesCommand`
Shows all libraries (and sections) loaded by binary. This command extends the GDB command `info files`, by retrieving more information from extra sources, and providing a better display. If an argument FILE is given, the output will grep information related to only that file. If an argument name is also given, the output will grep to the name within FILE. 

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> XFilesCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XFilesCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XFilesCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XorMemoryCommand`
XOR a block of memory. The command allows to simply display the result, or patch it runtime at runtime. 

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> XorMemoryCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.do_invoke`

```python
do_invoke(_: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XorMemoryDisplayCommand`
Display a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be provided in hexadecimal format. 

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> XorMemoryDisplayCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryDisplayCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryDisplayCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XorMemoryPatchCommand`
Patch a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be provided in hexadecimal format. 

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.__init__"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.__init__`

```python
__init__(*args: Any, **kwargs: Any) → None
```






---

#### <kbd>property</kbd> XorMemoryPatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.add_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.del_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.do_invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.do_invoke`

```python
do_invoke(argv: List[str]) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.get_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.get_setting`

```python
get_setting(name: str) → Any
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.has_setting"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.invoke"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.post_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.pre_load"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://cs.github.com/hugsy/gef?q=XorMemoryPatchCommand.usage"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `XorMemoryPatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Zone`
Zone(name, zone_start, zone_end, filename) 





---

## <kbd>class</kbd> `classproperty`
Make the attribute a `classproperty`. 







---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
