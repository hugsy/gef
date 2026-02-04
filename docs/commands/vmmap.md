## Command `vmmap`

`vmmap` displays the target process's entire memory space mapping.

![vmmap](docs/assets/images/vmmap.png)

Interestingly, it helps finding secret gems: as an aware reader might have seen, memory mapping
differs from one architecture to another (this is one of the main reasons I started `GEF` in a first
place). For example, you can learn that ELF running on SPARC architectures always have their `.data`
and `heap` sections set as Read/Write/Execute.

`vmmap` can accept multiple arguments, either patterns to match again mapping names, or addresses
to determine which section it belongs to:

1.  `-a` / `--addr`:
    -  filter by address -> parses the next argument as an integer or asks gdb to interpret the value
2.  `-n` / `--name`:
    -  filter based on section name
3.  If nothing is specified, it prints a warning and guesses the type

![vmmap-grep](https://github.com/hugsy/gef/assets/11377623/a3dbaa3e-88b0-407f-a0dd-07e65c4a3f73)

![vmmap-address](https://github.com/hugsy/gef/assets/11377623/4dffe491-f927-4f03-b842-4d941140e66c)

The address can be also be given in the form of a register or variable.

![vmmap-register](https://github.com/hugsy/gef/assets/11377623/aed7ecdc-7ad9-4ba5-ae03-329e66432731)

And you can do all of them in one command 🙂

![vmmap-all-in-one](https://github.com/hugsy/gef/assets/11377623/b043f61b-48b3-4316-9f84-eb83822149ac)
