## Command hexdump

Gimmick of the WinDBG command.

This command requires at least 2 arguments, the format for representing the
data, and a value/address/symbol used as the location to print the hexdump
from. An optional 3rd argument is used to specify the number of
qword/dword/word/bytes to display.

The command provides WinDBG compatible aliases by default:

  - `hexdump qword` -> `dq`
  - `hexdump dword` -> `dd`
  - `hexdump word` -> `dw`
  - `hexdump byte` -> `dc`

`hexdump byte` will also try to display the ASCII character values if the byte
is printable (similarly to the `hexdump -C` command on Linux).
