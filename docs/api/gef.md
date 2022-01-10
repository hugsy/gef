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
- **gef**
- **pattern_libc_ver**
- **PREFIX**
- **gdb_initial_settings**
- **cmd**

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `FakeExit`

```python
FakeExit(*args, **kwargs) → None
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `align_address`

```python
align_address(address: int) → int
```

Align the provided address to the process's native length. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `align_address_to_page`

```python
align_address_to_page(address: int) → int
```

Align the address to a page. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `align_address_to_size`

```python
align_address_to_size(address: int, align: int) → int
```

Align the address to the given size. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `bufferize`

```python
bufferize(f: Callable) → Callable
```

Store the content to be printed for a function in memory, and flush it on function exit. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `capstone_disassemble`

```python
capstone_disassemble(location: int, nb_insn: int, **kwargs)
```

Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr` using the Capstone-Engine disassembler, if available. Return an iterator of Instruction objects. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `clear_screen`

```python
clear_screen(tty: str = '') → None
```

Clear the screen. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `continue_handler`

```python
continue_handler(event) → None
```

GDB event handler for new object continue cases. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `copy_to_clipboard`

```python
copy_to_clipboard(data: str) → None
```

Helper function to submit data to the clipboard 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `de_bruijn`

```python
de_bruijn(alphabet: str, n: int) → Generator[str, NoneType, NoneType]
```

De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib). 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `deprecated`

```python
deprecated(solution: str = '') → Callable
```

Decorator to add a warning when a command is obsolete and will be removed. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `disable_redirect_output`

```python
disable_redirect_output() → None
```

Disable the output redirection, if any. `disable_redirect_output` is **DEPRECATED** and will be removed in the future. Use `RedirectOutputContext()` context manager 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `download_file`

```python
download_file(
    remote_path: str,
    use_cache: bool = False,
    local_name: Optional[str] = None
) → Union[str, NoneType]
```

Download filename `remote_path` inside the mirror tree inside the gef.config["gef.tempdir"]. The tree architecture must be gef.config["gef.tempdir"]/gef/<local_pid>/<remote_filepath>. This allow a "chroot-like" tree format. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `enable_redirect_output`

```python
enable_redirect_output(to_file: str = '/dev/null') → None
```

Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`. `enable_redirect_output` is **DEPRECATED** and will be removed in the future. Use `RedirectOutputContext()` context manager 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `endian_str`

```python
endian_str() → str
```

`endian_str` is **DEPRECATED** and will be removed in the future. Use `str(gef.arch.endianness)` instead 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `err`

```python
err(msg: str) → Union[int, NoneType]
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `exit_handler`

```python
exit_handler(event) → None
```

GDB event handler for exit cases. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `experimental_feature`

```python
experimental_feature(f: Callable) → Callable
```

Decorator to add a warning when a feature is experimental. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `flags_to_human`

```python
flags_to_human(reg_value: int, value_table: Dict[int, str]) → str
```

Return a human readable string showing the flag states. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `format_address`

```python
format_address(addr: int) → str
```

Format the address according to its size. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `format_address_spaces`

```python
format_address_spaces(addr: int, left: bool = True) → str
```

Format the address according to its size, but with spaces instead of zeroes. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gdb_disassemble`

```python
gdb_disassemble(start_pc: int, **kwargs: int)
```

Disassemble instructions from `start_pc` (Integer). Accepts the following named parameters: 
- `end_pc` (Integer) only instructions whose start address fall in the interval from start_pc to end_pc are returned. 
- `count` (Integer) list at most this many disassembled instructions If `end_pc` and `count` are not provided, the function will behave as if `count=1`. Return an iterator of Instruction objects 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gdb_get_nth_next_instruction_address`

```python
gdb_get_nth_next_instruction_address(addr: int, n: int) → int
```

Return the address (Integer) of the `n`-th instruction after `addr`. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gdb_get_nth_previous_instruction_address`

```python
gdb_get_nth_previous_instruction_address(
    addr: int,
    n: int
) → Union[int, NoneType]
```

Return the address (Integer) of the `n`-th instruction before `addr`. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_convenience`

```python
gef_convenience(value: str) → str
```

Defines a new convenience value. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_current_instruction`

```python
gef_current_instruction(addr: int)
```

Return the current instruction as an Instruction object. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_disassemble`

```python
gef_disassemble(addr: int, nb_insn: int, nb_prev: int = 0)
```

Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`. Return an iterator of Instruction objects. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_execute_external`

```python
gef_execute_external(
    command: Sequence[str],
    as_list: bool = False,
    **kwargs
) → Union[str, List[str]]
```

Execute an external command and return the result. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_execute_gdb_script`

```python
gef_execute_gdb_script(commands: str) → None
```

Execute the parameter `source` as GDB command. This is done by writing `commands` to a temporary file, which is then executed via GDB `source` command. The tempfile is then deleted. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_get_instruction_at`

```python
gef_get_instruction_at(addr: int)
```

Return the full Instruction found at the specified address. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_get_pie_breakpoint`

```python
gef_get_pie_breakpoint(num: int)
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_getpagesize`

```python
gef_getpagesize() → int
```

`gef_getpagesize` is **DEPRECATED** and will be removed in the future. Use `gef.session.pagesize` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_instruction_n`

```python
gef_instruction_n(addr: int, n: int)
```

Return the `n`-th instruction after `addr` as an Instruction object. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_makedirs`

```python
gef_makedirs(path: str, mode: int = 493) → str
```

Recursive mkdir() creation. If successful, return the absolute path of the directory created. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_next_instruction`

```python
gef_next_instruction(addr: int)
```

Return the next instruction as an Instruction object. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `wrapped_f`

```python
wrapped_f(*args: Tuple, **kwargs: Dict) → Any
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_print`

```python
gef_print(x: str = '', *args: Tuple, **kwargs: Dict) → Union[int, NoneType]
```

Wrapper around print(), using string buffering feature. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_pybytes`

```python
gef_pybytes(x: str) → bytes
```

Returns an immutable bytes list from the string given as input. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_pystring`

```python
gef_pystring(x: bytes) → str
```

Returns a sanitized version as string of the bytes list given in input. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `gef_read_canary`

```python
gef_read_canary() → Union[Tuple[int, int], NoneType]
```

`gef_read_canary` is **DEPRECATED** and will be removed in the future. Use `gef.session.canary` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `generate_cyclic_pattern`

```python
generate_cyclic_pattern(length: int, cycle: int = 4) → bytearray
```

Create a `length` byte bytearray of a de Bruijn cyclic pattern. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_filename`

```python
get_filename() → str
```

`get_filename` is **DEPRECATED** and will be removed in the future. Use `gef.session.file.name` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_function_length`

```python
get_function_length(sym)
```

Attempt to get the length of the raw bytes of a function. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_gef_setting`

```python
get_gef_setting(name: str) → Any
```

`get_gef_setting` is **DEPRECATED** and will be removed in the future. Use `gef.config[key]` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_glibc_arena`

```python
get_glibc_arena()
```

`get_glibc_arena` is **DEPRECATED** and will be removed in the future. Use `gef.heap.main_arena` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_memory_alignment`

```python
get_memory_alignment(in_bits: bool = False) → int
```

Try to determine the size of a pointer on this system.  First, try to parse it out of the ELF header.  Next, use the size of `size_t`.  Finally, try the size of $pc.  If `in_bits` is set to True, the result is returned in bits, otherwise in  bytes. `get_memory_alignment` is **DEPRECATED** and will be removed in the future. Use `gef.arch.ptrsize` instead 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_os`

```python
get_os() → str
```

`get_os` is **DEPRECATED** and will be removed in the future. Use `gef.session.os` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_path_from_info_proc`

```python
get_path_from_info_proc()
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_pid`

```python
get_pid() → int
```

`get_pid` is **DEPRECATED** and will be removed in the future. Use `gef.session.pid` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_process_maps`

```python
get_process_maps()
```

`get_process_maps` is **DEPRECATED** and will be removed in the future. Use `gef.memory.maps` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_register`

```python
get_register(regname)
```

`get_register` is **DEPRECATED** and will be removed in the future. Use `gef.arch.register(regname)` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_terminal_size`

```python
get_terminal_size() → Tuple[int, int]
```

Return the current terminal size. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `get_unicorn_registers`

```python
get_unicorn_registers(
    to_string: bool = False
) → Union[Dict[str, int], Dict[str, str]]
```

Return a dict matching the Unicorn identifier for a specific register. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `hide_context`

```python
hide_context() → bool
```

Helper function to hide the context pane  


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `highlight_text`

```python
highlight_text(text: str) → str
```

Highlight text using gef.ui.highlight_table { match -> color } settings. 

If RegEx is enabled it will create a match group around all items in the gef.ui.highlight_table and wrap the specified color in the gef.ui.highlight_table around those matches. 

If RegEx is disabled, split by ANSI codes and 'colorify' each match found within the specified string. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `hook_stop_handler`

```python
hook_stop_handler(event) → None
```

GDB event handler for stop cases. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `http_get`

```python
http_get(url: str) → Union[bytes, NoneType]
```

Basic HTTP wrapper for GET request. Return the body of the page if HTTP code is OK, otherwise return None. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ida_synchronize_handler`

```python
ida_synchronize_handler(event)
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `info`

```python
info(msg: str) → Union[int, NoneType]
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_alive`

```python
is_alive() → bool
```

Check if GDB is running. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_ascii_string`

```python
is_ascii_string(address: int) → bool
```

Helper function to determine if the buffer pointed by `address` is an ASCII string (in GDB) 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_big_endian`

```python
is_big_endian() → bool
```

`is_big_endian` is **DEPRECATED** and will be removed in the future. Prefer `gef.arch.endianness == Endianness.BIG_ENDIAN` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_debug`

```python
is_debug() → bool
```

Check if debug mode is enabled. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_hex`

```python
is_hex(pattern: str) → bool
```

Return whether provided string is a hexadecimal value. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_in_x86_kernel`

```python
is_in_x86_kernel(address: int) → bool
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_little_endian`

```python
is_little_endian() → bool
```

`is_little_endian` is **DEPRECATED** and will be removed in the future. gef.arch.endianness == Endianness.LITTLE_ENDIAN 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `is_pie`

```python
is_pie(fpath: str) → bool
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `keystone_assemble`

```python
keystone_assemble(
    code: str,
    arch: int,
    mode: int,
    *args,
    **kwargs
) → Union[str, bytearray, NoneType]
```

Assembly encoding function based on keystone. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `load_libc_args`

```python
load_libc_args() → None
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `malloc_align_address`

```python
malloc_align_address(address: int) → int
```

Align addresses according to glibc's MALLOC_ALIGNMENT. See also Issue #689 on Github 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `memchanged_handler`

```python
memchanged_handler(event) → None
```

GDB event handler for mem changes cases. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `new_objfile_handler`

```python
new_objfile_handler(event) → None
```

GDB event handler for new object file cases. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `ok`

```python
ok(msg: str) → Union[int, NoneType]
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_current_arch_in`

```python
only_if_current_arch_in(valid_architectures: List) → Callable
```

Decorator to allow commands for only a subset of the architectured supported by GEF. This decorator is to use lightly, as it goes against the purpose of GEF to support all architectures GDB does. However in some cases, it is necessary. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_events_supported`

```python
only_if_events_supported(event_type) → Callable
```

Checks if GDB supports events without crashing. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_gdb_running`

```python
only_if_gdb_running(f: Callable) → Callable
```

Decorator wrapper to check if GDB is running. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_gdb_target_local`

```python
only_if_gdb_target_local(f: Callable) → Callable
```

Decorator wrapper to check if GDB is running locally (target not remote). 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `only_if_gdb_version_higher_than`

```python
only_if_gdb_version_higher_than(required_gdb_version) → Callable
```

Decorator to check whether current GDB version requirements. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p16`

```python
p16(x: int, s: bool = False) → bytes
```

Pack one word respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p32`

```python
p32(x: int, s: bool = False) → bytes
```

Pack one dword respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p64`

```python
p64(x: int, s: bool = False) → bytes
```

Pack one qword respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `p8`

```python
p8(x: int, s: bool = False) → bytes
```

Pack one byte respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_address`

```python
parse_address(address: str) → int
```

Parse an address and return it as an Integer. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_arguments`

```python
parse_arguments(
    required_arguments: Dict,
    optional_arguments: Dict
) → Union[Callable, NoneType]
```

Argument parsing decorator. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `parse_string_range`

```python
parse_string_range(s: str) → Iterator[int]
```

Parses an address range (e.g. 0x400000-0x401000) 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `process_lookup_address`

```python
process_lookup_address(address: int)
```

Look up for an address in memory. Return an Address object if found, None otherwise. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `push_context_message`

```python
push_context_message(level: str, message: str) → None
```

Push the message to be displayed the next time the context is invoked. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `regchanged_handler`

```python
regchanged_handler(event) → None
```

GDB event handler for reg changes cases. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_architecture`

```python
register_architecture(cls)
```

Class decorator for declaring an architecture to GEF. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_command`

```python
register_command(cls)
```

Decorator for registering new GEF (sub-)command to GDB. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_external_command`

```python
register_external_command(obj)
```

Registering function for new GEF (sub-)command to GDB. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_function`

```python
register_function(cls)
```

Decorator for registering a new convenience function to GDB. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `register_priority_command`

```python
register_priority_command(cls)
```

Decorator for registering new command with priority, meaning that it must loaded before the other generic commands. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `reset`

```python
reset() → None
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `reset_all_caches`

```python
reset_all_caches() → None
```

Free all caches. If an object is cached, it will have a callable attribute `cache_clear` which will be invoked to purge the function cache. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `safe_parse_and_eval`

```python
safe_parse_and_eval(value: str)
```

GEF wrapper for gdb.parse_and_eval(): this function returns None instead of raising gdb.error if the eval failed. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `set_arch`

```python
set_arch(arch=None, default=None)
```

Sets the current architecture. If an arch is explicitly specified, use that one, otherwise try to parse it out of the current target. If that fails, and default is specified, select and set that arch. Return the selected arch, or raise an OSError. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `set_gef_setting`

```python
set_gef_setting(name: str, value: Any) → None
```

`set_gef_setting` is **DEPRECATED** and will be removed in the future. Use `gef.config[key] = value` 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `show_last_exception`

```python
show_last_exception() → None
```

Display the last Python exception. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `style_byte`

```python
style_byte(b: int, color: bool = True) → str
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `to_unsigned_long`

```python
to_unsigned_long(v) → int
```

Cast a gdb.Value to unsigned long. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u16`

```python
u16(x: bytes, s: bool = False) → int
```

Unpack one word respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u32`

```python
u32(x: bytes, s: bool = False) → int
```

Unpack one dword respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u64`

```python
u64(x: bytes, s: bool = False) → int
```

Unpack one qword respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `u8`

```python
u8(x: bytes, s: bool = False) → int
```

Unpack one byte respecting the current architecture endianness. 


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `unhide_context`

```python
unhide_context() → bool
```

Helper function to unhide the context pane  


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `update_gef`

```python
update_gef(argv: List[str]) → int
```

Try to update `gef` to the latest version pushed on GitHub master branch. Return 0 on success, 1 on failure.  


---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_default_type`

```python
use_default_type() → str
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_golang_type`

```python
use_golang_type() → str
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_rust_type`

```python
use_rust_type() → str
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `use_stdtype`

```python
use_stdtype() → str
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `warn`

```python
warn(msg: str) → Union[int, NoneType]
```






---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

## <kbd>function</kbd> `xor`

```python
xor(data: ByteString, key: str) → bytearray
```

Return `data` xor-ed with `key`. 


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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.get_ra`

```python
get_ra(insn, frame) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.is_ret`

```python
is_ret(insn) → Union[bool, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.is_thumb`

```python
is_thumb() → bool
```

Determine if the machine is currently in THUMB mode. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `AARCH64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AARCH64.register`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.get_ra`

```python
get_ra(insn, frame) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.is_ret`

```python
is_ret(insn) → Union[bool, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.is_thumb`

```python
is_thumb() → bool
```

Determine if the machine is currently in THUMB mode. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `ARM.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ARM.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `ASLRCommand`
View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not attached). This command allows to change that setting. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> ASLRCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ASLRCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Address`
GEF representation of memory addresses. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Address.__init__`

```python
__init__(*args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Address.dereference`

```python
dereference() → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Address.is_in_heap_segment`

```python
is_in_heap_segment() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Address.is_in_stack_segment`

```python
is_in_stack_segment() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Address.is_in_text_segment`

```python
is_in_text_segment() → bool
```






---

## <kbd>class</kbd> `AliasesAddCommand`
Command to add aliases. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesAddCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesAddCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `AliasesCommand`
Base command to add, remove, or list aliases. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.do_invoke`

```python
do_invoke(argv) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `AliasesListCommand`
Command to list aliases. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesListCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `AliasesRmCommand`
Command to remove aliases. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AliasesRmCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AliasesRmCommand.usage`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.is_ret`

```python
is_ret(insn) → Union[bool, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Architecture.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `AssembleCommand`
Inline code assemble. Architecture can be set in GEF runtime config.  

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> AssembleCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `AssembleCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.list_archs`

```python
list_archs() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `AssembleCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `BssBaseFunction`
Return the current bss base address plus the given offset. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `BssBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `BssBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `BssBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `BssBaseFunction.invoke`

```python
invoke(*args) → int
```






---

## <kbd>class</kbd> `CanaryCommand`
Shows the canary value of the current process. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> CanaryCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CanaryCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `CapstoneDisassembleCommand`
Use capstone disassembly framework to disassemble code. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.__init__`

```python
__init__()
```






---

#### <kbd>property</kbd> CapstoneDisassembleCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.capstone_analyze_pc`

```python
capstone_analyze_pc(insn, nb_insn: int) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `CapstoneDisassembleCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `CapstoneDisassembleCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ChangeFdCommand`
ChangeFdCommand: redirect file descriptor during runtime. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> ChangeFdCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.get_fd_from_result`

```python
get_fd_from_result(res: str) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangeFdCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ChangePermissionBreakpoint`
When hit, this temporary breakpoint will restore the original code, and position $pc correctly. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionBreakpoint.__init__`

```python
__init__(loc: str, code: ByteString, pc: int) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `ChangePermissionCommand`
Change a page permission. By default, it will change it to 7 (RWX). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ChangePermissionCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.get_stub_by_arch`

```python
get_stub_by_arch(addr: int, size: int, perm) → Union[str, bytearray, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChangePermissionCommand.usage`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ChecksecCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.print_security_properties`

```python
print_security_properties(filename: str) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ChecksecCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Color`
Used to colorify terminal output. 




---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.blinkify`

```python
blinkify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.blueify`

```python
blueify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.boldify`

```python
boldify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.colorify`

```python
colorify(text: str, attrs: str) → str
```

Color text according to the given attributes. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.cyanify`

```python
cyanify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.grayify`

```python
grayify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.greenify`

```python
greenify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.highlightify`

```python
highlightify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.light_grayify`

```python
light_grayify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.pinkify`

```python
pinkify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.redify`

```python
redify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.underlinify`

```python
underlinify(msg: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Color.yellowify`

```python
yellowify(msg: str) → str
```






---

## <kbd>class</kbd> `ContextCommand`
Displays a comprehensive and modular summary of runtime context. Unless setting `enable` is set to False, this command will be spawned automatically every time GDB hits a breakpoint, a watchpoint, or any kind of interrupt. By default, it will show panes that contain the register states, the stack, and the disassembly code around $pc. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ContextCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.addr_has_breakpoint`

```python
addr_has_breakpoint(address: int, bp_locations: List[str]) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_additional_information`

```python
context_additional_information() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_args`

```python
context_args() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_code`

```python
context_code() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_memory`

```python
context_memory() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_regs`

```python
context_regs() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_source`

```python
context_source() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_stack`

```python
context_stack() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_threads`

```python
context_threads() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_title`

```python
context_title(m: Optional[str]) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.context_trace`

```python
context_trace() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.empty_extra_messages`

```python
empty_extra_messages(_) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.get_pc_context_info`

```python
get_pc_context_info(pc: int, line: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.line_has_breakpoint`

```python
line_has_breakpoint(
    file_name: str,
    line_number: int,
    bp_locations: List[str]
) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.print_arguments_from_symbol`

```python
print_arguments_from_symbol(function_name: str, symbol) → None
```

If symbols were found, parse them and print the argument adequately. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.print_guessed_arguments`

```python
print_guessed_arguments(function_name: str) → None
```

When no symbol, read the current basic block and look for "interesting" instructions. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.show_legend`

```python
show_legend() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `ContextCommand.update_registers`

```python
update_registers(_) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ContextCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `DereferenceCommand`
Dereference recursively from an address and display information. This acts like WinDBG `dps` command. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> DereferenceCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `DereferenceCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.pprint_dereferenced`

```python
pprint_dereferenced(addr: int, idx: int, base_offset: int = 0) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DereferenceCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `DetailRegistersCommand`
Display full details on one, many or all registers value from current architecture. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> DetailRegistersCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `DetailRegistersCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `DetailRegistersCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Elf`
Basic ELF parsing. Ref: 
- http://www.skyfree.org/linux/references/ELF_Format.pdf 
- http://refspecs.freestandards.org/elf/elfspec_ppc.pdf 
- http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Elf.__init__`

```python
__init__(elf: str = '', minimalist: bool = False) → None
```

Instantiate an ELF object. The default behavior is to create the object by parsing the ELF file. But in some cases (QEMU-stub), we may just want a simple minimal object with default values. 




---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Elf.is_valid`

```python
is_valid() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Elf.read`

```python
read(size)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Elf.seek`

```python
seek(off: int) → None
```






---

## <kbd>class</kbd> `ElfInfoCommand`
Display a limited subset of ELF header information. If no argument is provided, the command will show information about the current ELF being debugged. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ElfInfoCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `ElfInfoCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ElfInfoCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Endianness`
An enumeration. 





---

## <kbd>class</kbd> `EntryBreakBreakpoint`
Breakpoint used internally to stop execution at the most convenient entry point. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryBreakBreakpoint.__init__`

```python
__init__(location: str) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryBreakBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `EntryPointBreakCommand`
Tries to find best entry point and sets a temporary breakpoint on it. The command will test for well-known symbols for entry points, such as `main`, `_main`, `__libc_start_main`, etc. defined by the setting `entrypoint_symbols`. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> EntryPointBreakCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.set_init_tbreak`

```python
set_init_tbreak(addr: int) → EntryBreakBreakpoint
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.set_init_tbreak_pie`

```python
set_init_tbreak_pie(addr: int, argv: List[str]) → EntryBreakBreakpoint
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `EntryPointBreakCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `FlagsCommand`
Edit flags in a human friendly way. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> FlagsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FlagsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `FormatStringBreakpoint`
Inspect stack for format string. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringBreakpoint.__init__`

```python
__init__(spec: str, num_args: int) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `FormatStringSearchCommand`
Exploitable format-string helper: this command will set up specific breakpoints at well-known dangerous functions (printf, snprintf, etc.), and check if the pointer holding the format string is writable, and therefore susceptible to format string attacks if an attacker can control its content. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> FormatStringSearchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `FormatStringSearchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GdbRemoveReadlineFinder`







---

<a href="../../<string>"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GdbRemoveReadlineFinder.find_module`

```python
find_module(fullname, path=None)
```





---

<a href="../../<string>"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GdbRemoveReadlineFinder.load_module`

```python
load_module(fullname)
```






---

## <kbd>class</kbd> `Gef`
The GEF root class, which serves as a base classe for all the attributes for the debugging session (architecture, memory, settings, etc.). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Gef.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Gef.reinitialize_managers`

```python
reinitialize_managers() → None
```

Reinitialize the managers. Avoid calling this function directly, using `pi reset()` is preferred 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Gef.reset_caches`

```python
reset_caches() → None
```

Recursively clean the cache of all the managers. Avoid calling this function directly, using `reset-cache` is preferred 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Gef.setup`

```python
setup() → None
```

Setup initialize the runtime setup, which may require for the `gef` to be not None. 


---

## <kbd>class</kbd> `GefAlias`
Simple aliasing wrapper because GDB doesn't do what it should. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefAlias.__init__`

```python
__init__(alias, command, completer_class=0, command_class=-1) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefAlias.invoke`

```python
invoke(args, from_tty) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefAlias.lookup_command`

```python
lookup_command(cmd: str) → Union[Tuple[str, Type, Any], NoneType]
```






---

## <kbd>class</kbd> `GefCommand`
GEF main command: view all new commands by typing `gef`. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefCommand.loaded_command_names







---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefCommand.add_context_pane`

```python
add_context_pane(
    pane_name: str,
    display_pane_function: Callable,
    pane_title_function: Callable
) → None
```

Add a new context pane to ContextCommand. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefCommand.invoke`

```python
invoke(args, from_tty) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefCommand.load`

```python
load(initial: bool = False) → None
```

Load all the commands and functions defined by GEF into GDB. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefCommand.setup`

```python
setup() → None
```






---

## <kbd>class</kbd> `GefConfigCommand`
GEF configuration sub-command This command will help set/view GEF settings for the current debugging session. It is possible to make those changes permanent by running `gef save` (refer to this command help), and/or restore previously saved settings by running `gef restore` (refer help). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefConfigCommand.__init__`

```python
__init__(loaded_commands, *args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefConfigCommand.complete`

```python
complete(text: str, word: str) → List[str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefConfigCommand.invoke`

```python
invoke(args: str, from_tty) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefConfigCommand.print_setting`

```python
print_setting(plugin_name: str, verbose: bool = False) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefConfigCommand.print_settings`

```python
print_settings() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefConfigCommand.set_setting`

```python
set_setting(argv: Tuple[str, Any]) → None
```






---

## <kbd>class</kbd> `GefFunctionsCommand`
List the convenience functions provided by GEF. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefFunctionsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.add_function_to_doc`

```python
add_function_to_doc(function) → None
```

Add function to documentation. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.do_invoke`

```python
do_invoke(argv) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.setup`

```python
setup() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefFunctionsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GefHeapManager`
Class managing session heap. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHeapManager.__init__`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHeapManager.reset_caches`

```python
reset_caches() → None
```






---

## <kbd>class</kbd> `GefHelpCommand`
GEF help sub-command. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHelpCommand.__init__`

```python
__init__(commands: List[Tuple[str, Any, Any]], *args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHelpCommand.add_command_to_doc`

```python
add_command_to_doc(command: Tuple[str, Any, Any]) → None
```

Add command to GEF documentation. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHelpCommand.generate_help`

```python
generate_help(commands: List[Tuple[str, Type, Any]]) → None
```

Generate builtin commands documentation. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHelpCommand.invoke`

```python
invoke(args, from_tty) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefHelpCommand.refresh`

```python
refresh() → None
```

Refresh the documentation. 


---

## <kbd>class</kbd> `GefManager`







---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefManager.reset_caches`

```python
reset_caches() → None
```

Reset the LRU-cached attributes 


---

## <kbd>class</kbd> `GefMemoryManager`
Class that manages memory access for gef. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GefMemoryManager.maps







---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.read`

```python
read(addr: int, length: int = 16) → bytes
```

Return a `length` long byte array with the copy of the process memory at `addr`. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.read_ascii_string`

```python
read_ascii_string(address: int) → Union[str, NoneType]
```

Read an ASCII string from memory 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.read_cstring`

```python
read_cstring(
    address: int,
    max_length: int = 50,
    encoding: Optional[str] = None
) → str
```

Return a C-string read from memory. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.read_integer`

```python
read_integer(addr: int) → int
```

Return an integer read from memory. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.reset_caches`

```python
reset_caches() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMemoryManager.write`

```python
write(address: int, buffer: ByteString, length: int = 16)
```

Write `buffer` at address `address`. 


---

## <kbd>class</kbd> `GefMissingCommand`
GEF missing sub-command Display the GEF commands that could not be loaded, along with the reason of why they could not be loaded. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMissingCommand.__init__`

```python
__init__(*args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefMissingCommand.invoke`

```python
invoke(args, from_tty) → None
```






---

## <kbd>class</kbd> `GefRestoreCommand`
GEF restore sub-command. Loads settings from file '~/.gef.rc' and apply them to the configuration of GEF. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefRestoreCommand.__init__`

```python
__init__(*args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefRestoreCommand.invoke`

```python
invoke(args: str, from_tty) → None
```






---

## <kbd>class</kbd> `GefRunCommand`
Override GDB run commands with the context from GEF. Simple wrapper for GDB run command to use arguments set from `gef set args`. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefRunCommand.__init__`

```python
__init__(*args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefRunCommand.invoke`

```python
invoke(args, from_tty) → None
```






---

## <kbd>class</kbd> `GefSaveCommand`
GEF save sub-command. Saves the current configuration of GEF to disk (by default in file '~/.gef.rc'). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSaveCommand.__init__`

```python
__init__(*args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSaveCommand.invoke`

```python
invoke(args, from_tty) → None
```






---

## <kbd>class</kbd> `GefSessionManager`
Class managing the runtime properties of GEF.  

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSessionManager.__init__`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSessionManager.reset_caches`

```python
reset_caches() → None
```






---

## <kbd>class</kbd> `GefSetCommand`
Override GDB set commands with the context from GEF. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSetCommand.__init__`

```python
__init__(*args, **kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSetCommand.invoke`

```python
invoke(args, from_tty) → None
```






---

## <kbd>class</kbd> `GefSetting`
Basic class for storing gef settings as objects 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSetting.__init__`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefSettingsManager.raw_entry`

```python
raw_entry(name: str) → Any
```






---

## <kbd>class</kbd> `GefThemeCommand`
Customize GEF appearance. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> GefThemeCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.do_invoke`

```python
do_invoke(args: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefThemeCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GefTmuxSetup`
Setup a confortable tmux debugging environment. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefTmuxSetup.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefTmuxSetup.invoke`

```python
invoke(args, from_tty) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefTmuxSetup.screen_setup`

```python
screen_setup() → None
```

Hackish equivalent of the tmux_setup() function for screen. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefTmuxSetup.tmux_setup`

```python
tmux_setup() → None
```

Prepare the tmux environment by vertically splitting the current pane, and forcing the context to be redirected there. 


---

## <kbd>class</kbd> `GefUiManager`
Class managing UI settings. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefUiManager.__init__`

```python
__init__()
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GefUiManager.reset_caches`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → Union[str, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericArchitecture.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `GenericCommand`
This is an abstract class for invoking commands, should not be instantiated. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> GenericCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GenericFunction`
This is an abstract class for invoking convenience functions, should not be instantiated. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericFunction.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericFunction.do_invoke`

```python
do_invoke(args) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GenericFunction.invoke`

```python
invoke(*args) → int
```






---

## <kbd>class</kbd> `GlibcArena`
Glibc arena class Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.__init__`

```python
__init__(addr: str) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.bin`

```python
bin(i: int) → Tuple[int, int]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.fastbin`

```python
fastbin(i: int)
```

Return head chunk in fastbinsY[i]. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.get_heap_for_ptr`

```python
get_heap_for_ptr(ptr: int) → int
```

Find the corresponding heap for a given pointer (int). See https://github.com/bminor/glibc/blob/glibc-2.34/malloc/arena.c#L129 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.get_heap_info_list`

```python
get_heap_info_list()
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.heap_addr`

```python
heap_addr(allow_unaligned: bool = False) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcArena.is_main_arena`

```python
is_main_arena() → bool
```






---

## <kbd>class</kbd> `GlibcChunk`
Glibc chunk class. The default behavior (from_base=False) is to interpret the data starting at the memory address pointed to as the chunk data. Setting from_base to True instead treats that data as the chunk header. Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.__init__`

```python
__init__(addr, from_base=False, allow_unaligned=True)
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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.flags_as_string`

```python
flags_as_string() → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_bkw_ptr`

```python
get_bkw_ptr() → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_chunk_size`

```python
get_chunk_size() → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_fwd_ptr`

```python
get_fwd_ptr(sll) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_next_chunk`

```python
get_next_chunk(allow_unaligned: bool = False)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_next_chunk_addr`

```python
get_next_chunk_addr() → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_prev_chunk_size`

```python
get_prev_chunk_size() → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.get_usable_size`

```python
get_usable_size() → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.has_m_bit`

```python
has_m_bit() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.has_n_bit`

```python
has_n_bit() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.has_p_bit`

```python
has_p_bit() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.is_used`

```python
is_used() → bool
```

Check if the current block is used by: 
- checking the M bit is true 
- or checking that next chunk PREV_INUSE flag is true 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.psprint`

```python
psprint() → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.str_as_alloced`

```python
str_as_alloced() → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.str_as_freed`

```python
str_as_freed() → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcChunk.str_chunk_size_flag`

```python
str_chunk_size_flag() → str
```






---

## <kbd>class</kbd> `GlibcHeapArenaCommand`
Display information on a heap chunk. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> GlibcHeapArenaCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapArenaCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapBinsCommand`
Display information on the bins on an arena (default: main_arena). See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.pprint_bin`

```python
pprint_bin(arena_addr: str, index: int, _type: str = '') → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapChunkCommand`
Display information on a heap chunk. See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapChunkCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `GlibcHeapChunkCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunkCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapChunksCommand`
Display all heap chunks for the current arena. As an optional argument the base address of a different arena can be passed 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapChunksCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `GlibcHeapChunksCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.dump_chunks_arena`

```python
dump_chunks_arena(
    arena: __main__.GlibcArena,
    print_arena: bool = False,
    allow_unaligned: bool = False
) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.dump_chunks_heap`

```python
dump_chunks_heap(
    start: int,
    until: Optional[int] = None,
    top: Optional[int] = None,
    allow_unaligned: bool = False
) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapChunksCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapCommand`
Base command to get information about the Glibc heap structure. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapFastbinsYCommand`
Display information on the fastbinsY on an arena (default: main_arena). See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapFastbinsYCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapFastbinsYCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapInfo`
Glibc heap_info struct See https://github.com/bminor/glibc/blob/glibc-2.34/malloc/arena.c#L64 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapInfo.__init__`

```python
__init__(addr) → None
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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapLargeBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapLargeBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapSetArenaCommand`
Display information on a heap chunk. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapSetArenaCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSetArenaCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapSmallBinsCommand`
Convenience command for viewing small bins. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapSmallBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapSmallBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapTcachebinsCommand`
Display information on the Tcachebins on an arena (default: main_arena). See https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapTcachebinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.check_thread_ids`

```python
check_thread_ids(tids: List[int]) → List[int]
```

Check the validity, dedup, and return all valid tids. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.find_tcache`

```python
find_tcache() → int
```

Return the location of the current thread's tcache. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.tcachebin`

```python
tcachebin(
    tcache_base: int,
    i: int
) → Tuple[Union[__main__.GlibcChunk, NoneType], int]
```

Return the head chunk in tcache[i] and the number of chunks in the bin. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapTcachebinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GlibcHeapUnsortedBinsCommand`
Display information on the Unsorted Bins of an arena (default: main_arena). See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> GlibcHeapUnsortedBinsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GlibcHeapUnsortedBinsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `GotBaseFunction`
Return the current bss base address plus the given offset. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotBaseFunction.invoke`

```python
invoke(*args) → int
```






---

## <kbd>class</kbd> `GotCommand`
Display current status of the got inside the process. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.__init__`

```python
__init__(*args, **kwargs)
```






---

#### <kbd>property</kbd> GotCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.get_jmp_slots`

```python
get_jmp_slots(readelf: str, filename: str) → List[str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `GotCommand.usage`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HeapAnalysisCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.clean`

```python
clean(_) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.dump_tracked_allocations`

```python
dump_tracked_allocations() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.setup`

```python
setup() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapAnalysisCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HeapBaseFunction`
Return the current heap base address plus an optional offset. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HeapBaseFunction.invoke`

```python
invoke(*args) → int
```






---

## <kbd>class</kbd> `HexdumpByteCommand`
Display SIZE lines of hexdump as BYTE from the memory location pointed by ADDRESS. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpByteCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `HexdumpByteCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpByteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpCommand`
Display SIZE lines of hexdump from the memory location pointed by LOCATION. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `HexdumpCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpDwordCommand`
Display SIZE lines of hexdump as DWORD from the memory location pointed by ADDRESS. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpDwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `HexdumpDwordCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpDwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpQwordCommand`
Display SIZE lines of hexdump as QWORD from the memory location pointed by ADDRESS. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpQwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `HexdumpQwordCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpQwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HexdumpWordCommand`
Display SIZE lines of hexdump as WORD from the memory location pointed by ADDRESS. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HexdumpWordCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `HexdumpWordCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HexdumpWordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightAddCommand`
Add a match to the highlight table. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> HighlightAddCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightAddCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightClearCommand`
Clear the highlight table, remove all matches. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> HighlightClearCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightClearCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightCommand`
Highlight user-defined text matches in GEF output universally. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> HighlightCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightListCommand`
Show the current highlight table with matches to colors. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> HighlightListCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.print_highlight_table`

```python
print_highlight_table() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `HighlightRemoveCommand`
Remove a match in the highlight table. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> HighlightRemoveCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `HighlightRemoveCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `IdaInteractCommand`
IDA Interact: set of commands to interact with IDA via a XML RPC service deployed via the IDA script `ida_gef.py`. It should be noted that this command can also be used to interact with Binary Ninja (using the script `binja_gef.py`) using the same interface. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> IdaInteractCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.connect`

```python
connect(host: Optional[str] = None, port: Optional[int] = None) → None
```

Connect to the XML-RPC service. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.disconnect`

```python
disconnect() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.do_invoke`

```python
do_invoke(argv: List) → None
```

`do_invoke` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.import_structures`

```python
import_structures(structs: Dict[str, List[Tuple[int, str, int]]]) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.is_target_alive`

```python
is_target_alive(host: str, port: int) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.synchronize`

```python
synchronize() → None
```

Submit all active breakpoint addresses to IDA/BN. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IdaInteractCommand.usage`

```python
usage(meth: Optional[str] = None) → None
```






---

## <kbd>class</kbd> `Instruction`
GEF representation of a CPU instruction. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Instruction.__init__`

```python
__init__(address: int, location, mnemo: str, operands, opcodes) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Instruction.is_valid`

```python
is_valid() → bool
```






---

## <kbd>class</kbd> `IsSyscallCommand`
Tells whether the next instruction is a system call. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> IsSyscallCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.is_syscall`

```python
is_syscall(arch, instruction: __main__.Instruction) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `IsSyscallCommand.usage`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `MIPS.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS.register`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `MIPS64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MIPS64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `MallocStateStruct`
GEF representation of malloc_state from https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c#L1658 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MallocStateStruct.__init__`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MallocStateStruct.get_size_t`

```python
get_size_t(addr)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MallocStateStruct.get_size_t_array`

```python
get_size_t_array(addr, length)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MallocStateStruct.get_size_t_pointer`

```python
get_size_t_pointer(addr)
```






---

## <kbd>class</kbd> `MemoryCommand`
Add or remove address ranges to the memory view. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> MemoryCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryUnwatchCommand`
Removes address ranges to the memory view. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> MemoryUnwatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryUnwatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryWatchCommand`
Adds address ranges to the memory view. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> MemoryWatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryWatchListCommand`
Lists all watchpoints to display in context layout. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> MemoryWatchListCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `MemoryWatchResetCommand`
Removes all watchpoints. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> MemoryWatchResetCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `MemoryWatchResetCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `NamedBreakpoint`
Breakpoint which shows a specified name, when hit. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpoint.__init__`

```python
__init__(location: str, name: str) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `NamedBreakpointCommand`
Sets a breakpoint and assigns a name to it, which will be shown, when it's hit. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> NamedBreakpointCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `NamedBreakpointCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NamedBreakpointCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `NopCommand`
Patch the instruction(s) pointed by parameters with NOP. Note: this command is architecture aware. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> NopCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `NopCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.get_insn_size`

```python
get_insn_size(addr: int) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.nop_bytes`

```python
nop_bytes(loc: int, num_bytes: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `NopCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomCommand`
Dump user defined structure. This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows to apply structures (from symbols or custom) directly to an address. Custom structures can be defined in pure Python using ctypes, and should be stored in a specific directory, whose path must be stored in the `pcustom.struct_path` configuration setting. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.apply_structure_to_address`

```python
apply_structure_to_address(
    mod_name: str,
    struct_name: str,
    addr: int,
    depth: int = 0
) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.deserialize`

```python
deserialize(struct: _ctypes.Structure, data: bytes) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.enumerate_structure_files`

```python
enumerate_structure_files() → List[str]
```

Return a list of all the files in the pcustom directory 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.enumerate_structures`

```python
enumerate_structures() → Dict[str, Set[str]]
```

Return a hash of all the structures, with the key set the to filepath 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.enumerate_structures_from_module`

```python
enumerate_structures_from_module(module: module) → Set[str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.get_ctypes_value`

```python
get_ctypes_value(struct, item, value) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.get_modulename_structname_from_arg`

```python
get_modulename_structname_from_arg(arg: str) → Tuple[str, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.get_pcustom_absolute_root_path`

```python
get_pcustom_absolute_root_path() → Union[str, bytes]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.get_pcustom_filepath_for_structure`

```python
get_pcustom_filepath_for_structure(structure_name: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.get_structure_class`

```python
get_structure_class(
    modname: str,
    classname: str
) → Tuple[Type, _ctypes.Structure]
```

Returns a tuple of (class, instance) if modname!classname exists 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.is_valid_struct`

```python
is_valid_struct(structure_name: str) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.load_module`

```python
load_module(file_path: str) → module
```

Load a custom module, and return it 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomEditCommand`
PCustom: edit the content of a given structure 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomEditCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.apply_structure_to_address`

```python
apply_structure_to_address(
    mod_name: str,
    struct_name: str,
    addr: int,
    depth: int = 0
) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.deserialize`

```python
deserialize(struct: _ctypes.Structure, data: bytes) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.enumerate_structure_files`

```python
enumerate_structure_files() → List[str]
```

Return a list of all the files in the pcustom directory 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.enumerate_structures`

```python
enumerate_structures() → Dict[str, Set[str]]
```

Return a hash of all the structures, with the key set the to filepath 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.enumerate_structures_from_module`

```python
enumerate_structures_from_module(module: module) → Set[str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.get_ctypes_value`

```python
get_ctypes_value(struct, item, value) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.get_modulename_structname_from_arg`

```python
get_modulename_structname_from_arg(arg: str) → Tuple[str, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.get_pcustom_absolute_root_path`

```python
get_pcustom_absolute_root_path() → Union[str, bytes]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.get_pcustom_filepath_for_structure`

```python
get_pcustom_filepath_for_structure(structure_name: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.get_structure_class`

```python
get_structure_class(
    modname: str,
    classname: str
) → Tuple[Type, _ctypes.Structure]
```

Returns a tuple of (class, instance) if modname!classname exists 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.is_valid_struct`

```python
is_valid_struct(structure_name: str) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.load_module`

```python
load_module(file_path: str) → module
```

Load a custom module, and return it 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomEditCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomListCommand`
PCustom: list available structures 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomListCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.apply_structure_to_address`

```python
apply_structure_to_address(
    mod_name: str,
    struct_name: str,
    addr: int,
    depth: int = 0
) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.deserialize`

```python
deserialize(struct: _ctypes.Structure, data: bytes) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.enumerate_structure_files`

```python
enumerate_structure_files() → List[str]
```

Return a list of all the files in the pcustom directory 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.enumerate_structures`

```python
enumerate_structures() → Dict[str, Set[str]]
```

Return a hash of all the structures, with the key set the to filepath 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.enumerate_structures_from_module`

```python
enumerate_structures_from_module(module: module) → Set[str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.get_ctypes_value`

```python
get_ctypes_value(struct, item, value) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.get_modulename_structname_from_arg`

```python
get_modulename_structname_from_arg(arg: str) → Tuple[str, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.get_pcustom_absolute_root_path`

```python
get_pcustom_absolute_root_path() → Union[str, bytes]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.get_pcustom_filepath_for_structure`

```python
get_pcustom_filepath_for_structure(structure_name: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.get_structure_class`

```python
get_structure_class(
    modname: str,
    classname: str
) → Tuple[Type, _ctypes.Structure]
```

Returns a tuple of (class, instance) if modname!classname exists 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.is_valid_struct`

```python
is_valid_struct(structure_name: str) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.load_module`

```python
load_module(file_path: str) → module
```

Load a custom module, and return it 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomListCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PCustomShowCommand`
PCustom: show the content of a given structure 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PCustomShowCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.apply_structure_to_address`

```python
apply_structure_to_address(
    mod_name: str,
    struct_name: str,
    addr: int,
    depth: int = 0
) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.deserialize`

```python
deserialize(struct: _ctypes.Structure, data: bytes) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.enumerate_structure_files`

```python
enumerate_structure_files() → List[str]
```

Return a list of all the files in the pcustom directory 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.enumerate_structures`

```python
enumerate_structures() → Dict[str, Set[str]]
```

Return a hash of all the structures, with the key set the to filepath 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.enumerate_structures_from_module`

```python
enumerate_structures_from_module(module: module) → Set[str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.get_ctypes_value`

```python
get_ctypes_value(struct, item, value) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.get_modulename_structname_from_arg`

```python
get_modulename_structname_from_arg(arg: str) → Tuple[str, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.get_pcustom_absolute_root_path`

```python
get_pcustom_absolute_root_path() → Union[str, bytes]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.get_pcustom_filepath_for_structure`

```python
get_pcustom_filepath_for_structure(structure_name: str) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.get_structure_class`

```python
get_structure_class(
    modname: str,
    classname: str
) → Tuple[Type, _ctypes.Structure]
```

Returns a tuple of (class, instance) if modname!classname exists 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.is_valid_struct`

```python
is_valid_struct(structure_name: str) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.load_module`

```python
load_module(file_path: str) → module
```

Load a custom module, and return it 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PCustomShowCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchByteCommand`
Write specified WORD to the specified address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchByteCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatchByteCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchByteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchCommand`
Write specified values to the specified address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatchCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchDwordCommand`
Write specified DWORD to the specified address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchDwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatchDwordCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchDwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchQwordCommand`
Write specified QWORD to the specified address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchQwordCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatchQwordCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchQwordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchStringCommand`
Write specified string to the specified memory location pointed by ADDRESS. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PatchStringCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchStringCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatchWordCommand`
Write specified WORD to the specified address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatchWordCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatchWordCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatchWordCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatternCommand`
Generate or Search a De Bruijn Sequence of unique substrings of length N and a total length of LENGTH. The default value of N is set to match the currently loaded architecture. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PatternCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatternCreateCommand`
Generate a De Bruijn Sequence of unique substrings of length N and a total length of LENGTH. The default value of N is set to match the currently loaded architecture. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PatternCreateCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatternCreateCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternCreateCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PatternSearchCommand`
Search a De Bruijn Sequence of unique substrings of length N and a maximum total length of MAX_LENGTH. The default value of N is set to match the currently loaded architecture. The PATTERN argument can be a GDB symbol (such as a register name), a string or a hexadecimal value 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PatternSearchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PatternSearchCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.search`

```python
search(pattern: str, size: int, period: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PatternSearchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Permission`
GEF representation of Linux permission. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Permission.__init__`

```python
__init__(**kwargs) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Permission.from_info_sections`

```python
from_info_sections(*args: List[str])
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Permission.from_process_maps`

```python
from_process_maps(perm_str: str)
```






---

## <kbd>class</kbd> `Phdr`




<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Phdr.__init__`

```python
__init__(elf: __main__.Elf, off: int) → None
```









---

## <kbd>class</kbd> `PieAttachCommand`
Do attach with PIE breakpoint support. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PieAttachCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieAttachCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieBreakpointCommand`
Set a PIE breakpoint at an offset from the target binaries base address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PieBreakpointCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PieBreakpointCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.set_pie_breakpoint`

```python
set_pie_breakpoint(set_func: Callable[[int], str], addr: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieBreakpointCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieCommand`
PIE breakpoint support. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PieCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieDeleteCommand`
Delete a PIE breakpoint. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PieDeleteCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.delete_bp`

```python
delete_bp(breakpoints: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PieDeleteCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieDeleteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieInfoCommand`
Display breakpoint info. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PieInfoCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PieInfoCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieInfoCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieRemoteCommand`
Attach to a remote connection with PIE breakpoint support. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PieRemoteCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRemoteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieRunCommand`
Run process with PIE breakpoint support. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> PieRunCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieRunCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `PieVirtualBreakpoint`
PIE virtual breakpoint (not real breakpoint). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieVirtualBreakpoint.__init__`

```python
__init__(set_func: Callable[[int], str], vbp_num: int, addr: int) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieVirtualBreakpoint.destroy`

```python
destroy() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PieVirtualBreakpoint.instantiate`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `PowerPC.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC.register`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `PowerPC64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PowerPC64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `PrintFormatCommand`
Print bytes format in high level languages. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> PrintFormatCommand.format_matrix





---

#### <kbd>property</kbd> PrintFormatCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `PrintFormatCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `PrintFormatCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ProcessListingCommand`
List and filter process. If a PATTERN is given as argument, results shown will be grepped by this pattern. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ProcessListingCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `ProcessListingCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.get_processes`

```python
get_processes() → Generator[Dict[str, str], Any, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessListingCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ProcessStatusCommand`
Extends the info given by GDB `info proc`, by giving an exhaustive description of the process status (file descriptors, ancestor, descendants, etc.). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ProcessStatusCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.get_children_pids`

```python
get_children_pids(pid: int) → List[int]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.get_cmdline_of`

```python
get_cmdline_of(pid: int) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.get_process_path_of`

```python
get_process_path_of(pid: int) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.get_state_of`

```python
get_state_of(pid: int) → Dict[str, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.list_sockets`

```python
list_sockets(pid: int) → List[int]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.parse_ip_port`

```python
parse_ip_port(addr: str) → Tuple[str, int]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.show_ancestor`

```python
show_ancestor() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.show_connections`

```python
show_connections() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.show_descendants`

```python
show_descendants() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.show_fds`

```python
show_fds() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.show_info_proc`

```python
show_info_proc() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ProcessStatusCommand.usage`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.get_ra`

```python
get_ra(insn, frame) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `RISCV.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RISCV.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `RedirectOutputContext`




<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RedirectOutputContext.__init__`

```python
__init__(to='/dev/null') → None
```









---

## <kbd>class</kbd> `RemoteCommand`
gef wrapper for the `target remote` command. This command will automatically download the target binary in the local temporary directory (defaut /tmp) and then source it. Additionally, it will fetch all the /proc/PID/maps and loads all its information. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> RemoteCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.connect_target`

```python
connect_target(target: str, is_extended_remote: bool) → bool
```

Connect to remote target and get symbols. To prevent `gef` from requesting information not fetched just yet, we disable the context disable when connection was successful. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `RemoteCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.load_from_remote_proc`

```python
load_from_remote_proc(pid: int, info: str) → Union[str, NoneType]
```

Download one item from /proc/pid. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.new_objfile_handler`

```python
new_objfile_handler(event) → None
```

Hook that handles new_objfile events, will update remote environment accordingly. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.prepare_qemu_stub`

```python
prepare_qemu_stub(target: str) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.refresh_shared_library_path`

```python
refresh_shared_library_path() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.setup_remote_environment`

```python
setup_remote_environment(pid: int, update_solib: bool = False) → None
```

Clone the remote environment locally in the temporary directory. The command will duplicate the entries in the /proc/<pid> locally and then source those information into the current gdb context to allow gef to use all the extra commands as it was local debugging. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RemoteCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ResetCacheCommand`
Reset cache of all stored data. This command is here for debugging and test purposes, GEF handles properly the cache reset under "normal" scenario. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> ResetCacheCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ResetCacheCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `RopperCommand`
Ropper (http://scoding.de/ropper) plugin. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> RopperCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `RopperCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SPARC`
Refs: 
- http://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf 


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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `SPARC.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC.register`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `SPARC64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SPARC64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `ScanSectionCommand`
Search for addresses that are located in a memory mapping (haystack) that belonging to another (needle). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> ScanSectionCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ScanSectionCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SearchPatternCommand`
SearchPatternCommand: search a pattern in memory. If given an hex value (starting with 0x) the command will also try to look for upwards cross-references to this address. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> SearchPatternCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.print_loc`

```python
print_loc(loc) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.print_section`

```python
print_section(section) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.search_pattern`

```python
search_pattern(pattern: str, section_name: str) → None
```

Search a pattern within the whole userland memory. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.search_pattern_by_address`

```python
search_pattern_by_address(
    pattern: str,
    start_address: int,
    end_address: int
) → List[Tuple[int, int, Union[str, NoneType]]]
```

Search a pattern within a range defined by arguments. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SearchPatternCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Section`
GEF representation of process memory sections. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Section.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> Section.realpath





---

#### <kbd>property</kbd> Section.size







---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Section.is_executable`

```python
is_executable() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Section.is_readable`

```python
is_readable() → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Section.is_writable`

```python
is_writable() → bool
```






---

## <kbd>class</kbd> `SectionBaseFunction`
Return the matching file's base address plus an optional offset. Defaults to current file. Note that quotes need to be escaped 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SectionBaseFunction.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SectionBaseFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SectionBaseFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SectionBaseFunction.invoke`

```python
invoke(*args) → int
```






---

## <kbd>class</kbd> `Shdr`




<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `Shdr.__init__`

```python
__init__(elf, off) → None
```









---

## <kbd>class</kbd> `ShellcodeCommand`
ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to download shellcodes. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> ShellcodeCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ShellcodeGetCommand`
Download shellcode from shell-storm's shellcode database. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> ShellcodeGetCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.get_shellcode`

```python
get_shellcode(sid: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeGetCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `ShellcodeSearchCommand`
Search pattern in shell-storm's shellcode database. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> ShellcodeSearchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.search_shellcode`

```python
search_shellcode(search_options: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `ShellcodeSearchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SmartEvalCommand`
SmartEval: Smart eval (vague approach to mimic WinDBG `?`). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> SmartEvalCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.distance`

```python
distance(args: Tuple[str, str])
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.evaluate`

```python
evaluate(expr: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SmartEvalCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SolveKernelSymbolCommand`
Solve kernel symbols from kallsyms table. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> SolveKernelSymbolCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `SolveKernelSymbolCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SolveKernelSymbolCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `StackOffsetFunction`
Return the current stack base address plus an optional offset. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StackOffsetFunction.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StackOffsetFunction.arg_to_long`

```python
arg_to_long(args: List, index: int, default: int = 0) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StackOffsetFunction.do_invoke`

```python
do_invoke(args: List) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StackOffsetFunction.invoke`

```python
invoke(*args) → int
```






---

## <kbd>class</kbd> `StubBreakpoint`
Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubBreakpoint.__init__`

```python
__init__(func: str, retval: Optional[int]) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `StubCommand`
Stub out the specified function. This function is useful when needing to skip one function to be called and disrupt your runtime flow (ex. fork). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> StubCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `StubCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `StubCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `SyscallArgsCommand`
Gets the syscall name and arguments based on the register values in the current state. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> SyscallArgsCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.get_filepath`

```python
get_filepath(x: str) → Union[str, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.get_module`

```python
get_module(modname: str)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.get_settings_path`

```python
get_settings_path() → Union[pathlib.Path, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.get_syscall_table`

```python
get_syscall_table(modname: str)
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `SyscallArgsCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `TraceFreeBreakpoint`
Track calls to free() and attempts to detect inconsistencies. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceFreeBreakpoint.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceFreeBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceFreeRetBreakpoint`
Internal temporary breakpoint to track free()d values. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceFreeRetBreakpoint.__init__`

```python
__init__(addr: int) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceFreeRetBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceMallocBreakpoint`
Track allocations done with malloc() or calloc(). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceMallocBreakpoint.__init__`

```python
__init__(name: str) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceMallocBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceMallocRetBreakpoint`
Internal temporary breakpoint to retrieve the return value of malloc(). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceMallocRetBreakpoint.__init__`

```python
__init__(size: int, name: str) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceMallocRetBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceReallocBreakpoint`
Track re-allocations done with realloc(). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceReallocBreakpoint.__init__`

```python
__init__() → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceReallocBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceReallocRetBreakpoint`
Internal temporary breakpoint to retrieve the return value of realloc(). 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceReallocRetBreakpoint.__init__`

```python
__init__(ptr: int, size: int) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceReallocRetBreakpoint.stop`

```python
stop() → bool
```






---

## <kbd>class</kbd> `TraceRunCommand`
Create a runtime trace of all instructions executed from $pc to LOCATION specified. The trace is stored in a text file that can be next imported in IDA Pro to visualize the runtime path. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> TraceRunCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.get_frames_size`

```python
get_frames_size() → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.start_tracing`

```python
start_tracing(loc_start: int, loc_end: int, depth: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.trace`

```python
trace(loc_start: int, loc_end: int, depth: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `TraceRunCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `UafWatchpoint`
Custom watchpoints set TraceFreeBreakpoint() to monitor free()d pointers being used. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UafWatchpoint.__init__`

```python
__init__(addr: int) → None
```








---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UafWatchpoint.stop`

```python
stop() → bool
```

If this method is triggered, we likely have a UaF. Break the execution and report it. 


---

## <kbd>class</kbd> `UnicornEmulateCommand`
Use Unicorn-Engine to emulate the behavior of the binary, without affecting the GDB runtime. By default the command will emulate only the next instruction, but location and number of instruction can be changed via arguments to the command line. By default, it will emulate the next instruction from current PC. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> UnicornEmulateCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `UnicornEmulateCommand.wrapper`

```python
wrapper(*args: Tuple, **kwargs: Dict) → Union[Callable, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.get_unicorn_end_addr`

```python
get_unicorn_end_addr(start_addr: int, nb: int) → int
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.run_unicorn`

```python
run_unicorn(start_insn_addr: int, end_insn_addr: int, *args, **kwargs) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `UnicornEmulateCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `VMMapCommand`
Display a comprehensive layout of the virtual memory mapping. If a filter argument, GEF will filter out the mapping whose pathname do not match that filter. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> VMMapCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.is_integer`

```python
is_integer(n: str) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.print_entry`

```python
print_entry(entry: __main__.Section) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.show_legend`

```python
show_legend() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VMMapCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `VersionCommand`
Display GEF version info. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> VersionCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `VersionCommand.usage`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `X86.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86.register`

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

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.flag_register_to_human`

```python
flag_register_to_human(val: Optional[int] = None) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.get_ith_parameter`

```python
get_ith_parameter(
    i: int,
    in_func: bool = True
) → Tuple[str, Union[int, NoneType]]
```

Retrieves the correct parameter used for the current function call. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.get_ra`

```python
get_ra(insn, frame) → Union[int, NoneType]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.is_branch_taken`

```python
is_branch_taken(insn) → Tuple[bool, str]
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.is_call`

```python
is_call(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.is_conditional_branch`

```python
is_conditional_branch(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.is_ret`

```python
is_ret(insn) → bool
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `X86_64.mprotect_asm`

```python
mprotect_asm(addr: int, size: int, perm) → str
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `X86_64.register`

```python
register(name: str) → Union[int, NoneType]
```






---

## <kbd>class</kbd> `XAddressInfoCommand`
Retrieve and display runtime information for the location(s) given as parameter. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> XAddressInfoCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.infos`

```python
infos(address: int) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XAddressInfoCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XFilesCommand`
Shows all libraries (and sections) loaded by binary. This command extends the GDB command `info files`, by retrieving more information from extra sources, and providing a better display. If an argument FILE is given, the output will grep information related to only that file. If an argument name is also given, the output will grep to the name within FILE. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> XFilesCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XFilesCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XorMemoryCommand`
XOR a block of memory. The command allows to simply display the result, or patch it runtime at runtime. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.__init__`

```python
__init__() → None
```






---

#### <kbd>property</kbd> XorMemoryCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XorMemoryDisplayCommand`
Display a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be provided in hexadecimal format. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> XorMemoryDisplayCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryDisplayCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `XorMemoryPatchCommand`
Patch a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be provided in hexadecimal format. 

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.__init__`

```python
__init__(*args, **kwargs) → None
```






---

#### <kbd>property</kbd> XorMemoryPatchCommand.settings

Return the list of settings for this command. 



---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.add_setting`

```python
add_setting(
    name: str,
    value: Tuple[Any, type, str],
    description: str = ''
) → None
```

`add_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.del_setting`

```python
del_setting(name: str) → None
```

`del_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.do_invoke`

```python
do_invoke(argv: List) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.get_setting`

```python
get_setting(name)
```

`get_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.has_setting`

```python
has_setting(name: str) → bool
```

`has_setting` is **DEPRECATED** and will be removed in the future. 

---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.invoke`

```python
invoke(args: str, from_tty: bool) → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.post_load`

```python
post_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.pre_load`

```python
pre_load() → None
```





---

<a href="https://github.com/hugsy/gef/blob/master/gef.py"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>method</kbd> `XorMemoryPatchCommand.usage`

```python
usage() → None
```






---

## <kbd>class</kbd> `Zone`
Zone(name, zone_start, zone_end, filename) 







---

_This file was automatically generated via [lazydocs](https://github.com/ml-tooling/lazydocs)._
