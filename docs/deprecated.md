# Deprecated commands

GEF is in itself a large file, but to avoid it to be out of control some commands once part of GEF were either moved to [GEF-Extras](https://github.com/hugsy/gef-extras) or even simply removed.
This page aims to track those changes.

| Command | Status | Since | Link (if Applicable) | Notes |
|--|--|--|--|--|
| `cs-disassemble` | Moved | 2022.06 | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/trinity/capstone.py) | Depends on `capstone` |
| `assemble` | Moved | 2022.06 | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/trinity/assemble.py) | Depends on `keystone` |
| `emulate` | Moved | 2022.06 | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/trinity/unicorn.py) | Depends on `unicorn` and `capstone` |
| `set-permission` | Moved | 2022.06 | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/trinity/mprotect.py) | Depends on `keystone` |
| `ropper` | Moved | 2022.06 | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/ropper.py) | Depends on `ropper` |
| `ida-interact` | Moved | 2022.06 | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/ida_interact.py) | Depends on `rpyc` |
| `exploit-template` | Moved | [c402900](https://github.com/hugsy/gef-extras/commit/c4029007994d5e508cb3df900b60821b0b61e0e5) | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/skel.py) | |
| `windbg` | Moved | [a933a5a](https://github.com/hugsy/gef-extras/commit/a933a5ac43933742d91f4e299eadf05e3e0670be) | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/windbg.py) | |
| `is-syscall` | Moved | [3f79fb38](https://github.com/hugsy/gef-extras/commit/3f79fb382aa9052d073698d40237f98982c5d2de) | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/syscall_args) | |
| `syscall-args` | Moved | [3f79fb38](https://github.com/hugsy/gef-extras/commit/3f79fb382aa9052d073698d40237f98982c5d2de) | [Link](https://github.com/hugsy/gef-extras/blob/dev/scripts/syscall_args) | |
