# Features #

This section will explain in details some non-trivial commands available in `GEF`
with examples and screenshots to make it easier to reproduce.

__Note__: if you consider the documentation to be imprecise/incomplete,
file an [Issue](https://github.com/hugsy/gef/issues/86) or better,
create a a [Pull Request](https://github.com/hugsy/gef/pulls) to the project to help
improve it.

| Command    | Description |
|:-----------|----------------:|
|`aliases`                   | Base command to add, remove, and list GEF defined aliases.|
|`aslr`                      | View/modify GDB ASLR behavior.|
|`assemble`                  | Inline code assemble. Architecture can be set in GEF runtime config (default is x86).  (alias: `asm`) |
|`capstone-disassemble`      | Use capstone disassembly framework to disassemble code. (alias: `cs-dis`) |
|`checksec`                  | Checksec.sh(https://www.trapkit.de/tools/checksec.html) port. |
|`context`                   | Display execution context. (alias: `ctx`)|
|`dereference`               | Dereference recursively an address and display information (alias: telescope, dps)|
|`edit-flags`                | Edit flags in a human friendly way (alias: `flags`)|
|`elf-info`                  | Display ELF header informations.|
|`entry-break`               | Tries to find best entry point and sets a temporary breakpoint on it. (alias: `start-break`)|
|`format-string-helper`      | Exploitable format string helper: this command will set up specific breakpoints at well-known dangerous functions (`printf`, `snprintf`, etc.), and check if the pointer holding the format string is writable, and  susceptible to format string attacks if an attacker can control its content. (alias: `fmtstr-helper`)|
|`functions`                 | List the convenience functions provided by GEF.|
|`gef`                       | Shows information about GEF commands and allows the user to configure settings.|
|`gef-remote`                | gef wrapper for the `target remote` command. This command will automatically download the target binary in the local temporary directory (defaut /tmp) and then source it. Additionally, it will fetch all the `/proc/PID/maps` and loads all its information.|
|`heap`                      | Base command to get information about the Glibc heap structure.|
|`heap-analysis-helper`      | Tracks dynamic heap allocation through `malloc`/`free` to try to detect heap vulnerabilities.|
|`hexdump`                   | Display arranged hexdump (according to architecture endianness) of memory range.|
|`highlight`                 | Highlight text using custom matches.|
|`hijack-fd`                 | Redirect file descriptor during runtime.|
|`ida-interact`              | IDA Interact: set of commands to interact with IDA via a XML RPC service deployed via the IDA script `ida_gef.py`. It should be noted that this command can also be used to interact with Binary Ninja (using the Binary Ninja plugin [`gef-binja`](https://github.com/hugsy/gef-binja)) using the same interface. (alias: `binaryninja-interact`, `bn`, `binja`)|
|`is-syscall`                | Tells whether the next instruction to be executed is a system call.|
|`ksymaddr`                  | Solve kernel symbols from kallsyms table.|
|`memory`                    | Add memory watches to the context view.|
|`nop`                       | Patch the instruction pointed by parameters with NOP. If the return option is specified, it will set the return register to the specific value.|
|`patch`                     | Write specified values to the specified address.|
|`pattern`                   | This command will create or search a De Bruijn cyclic pattern to facilitate determining the offset in memory. The algorithm used is the same as the one used by pwntools, and can therefore be used in conjunction.|
|`pcustom`                   | Dump user defined structure. This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows to apply structures (from symbols or custom) directly to an address. Custom structures can be defined in pure Python using ctypes, and should be stored in a specific directory, whose path must be stored in the `pcustom.struct_path` configuration setting. (alias: `dt`)|
|`pie`                       | Base command to support PIE breakpoints. PIE breakpoints is that you can set to a PIE binary, and use pie series commands to attach or create a new process, and it will automatically set the real breakpoint when the binary is running.
|`print-format`              | Command to dump memory in a variety of formats, such as programming language array literals. (alias: `pf`)|
|`process-search`            | List and filter process. (alias: `ps`)|
|`process-status`            | Extends the info given by GDB `info proc`, by giving an exhaustive description of the process status.|
|`registers`                 | Display full details on one, many or all registers value from current architecture.|
|`reset-cache`               | Reset cache of all stored data.|
|`ropper`                    | Ropper (https://scoding.de/ropper) plugin for GEF|
|`scan`                      | Search for addresses that are located in a memory mapping (haystack) that belonging to another (needle). (alias: `lookup`)|
|`search-pattern`            | SearchPatternCommand: search a pattern in memory. (alias: `grep`)|
|`set-permission`            | Change a page permission. By default, it will change it to RWX. (alias: `mprotect`)|
|`shellcode`                 | ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to download shellcodes.|
|`stub`                      | Stub out the specified function.|
|`syscall-args`              | Gets the syscall name and arguments based on the register values in the current state.|
|`trace-run`                 | Create a runtime trace of all instructions executed from `$pc` to LOCATION specified.|
|`unicorn-emulate`           | Use Unicorn-Engine to emulate the behavior of the binary, without affecting the GDB runtime. By default the command will emulate only the next instruction, but location and number of instruction can be changed via arguments to the command line. By default, it will emulate the next instruction from current PC. (alias: `emulate`)|
|`vmmap`                     | Display virtual memory mapping|
|`xfiles`                    | Shows all libraries (and sections) loaded by binary (The truth is out there).|
|`xinfo`                     | Get virtual section information for specific address|
|`xor-memory`                | XOR a block of memory.|
