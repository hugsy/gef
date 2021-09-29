from typing import Iterable, Union, NewType, List
import re
import subprocess
import os
import sys
import platform

PATH_TO_DEFAULT_BINARY = "/tmp/default.out"
STRIP_ANSI_DEFAULT = True
DEFAULT_CONTEXT = "-code -stack"
ARCH = (os.getenv("GEF_CI_ARCH") or platform.machine()).lower()
CI_VALID_ARCHITECTURES = ("x86_64", "i686", "aarch64", "armv7l")

CommandType = NewType("CommandType", Union[str, Iterable[str]])


def is_64b() -> bool:
    return ARCH in ("x86_64", "aarch64")


def ansi_clean(s: str) -> str:
    ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", s)


def _add_command(commands: CommandType) -> List[str]:
    if type(commands) == str:
        commands = [commands]
    return [_str for cmd in commands for _str in ["-ex", cmd]]


def gdb_run_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                target: str = PATH_TO_DEFAULT_BINARY, strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = [
        "gdb", "-q", "-nx",
        "-ex", "source /tmp/gef.py",
        "-ex", "gef config gef.debug True"
    ]

    command += _add_command(before)
    command += _add_command(cmd)
    command += _add_command(after)
    command += ["-ex", "quit", "--", target]

    lines = subprocess.check_output(command, stderr=subprocess.STDOUT).strip().splitlines()
    output = b"\n".join(lines)
    result = None

    # The following is necessary because ANSI escape sequences might have been
    # added in the middle of multibyte characters, e.g. \x1b[H\x1b[2J is added
    # into the middle of \xe2\x94\x80 to become \xe2\x1b[H\x1b[2J\x94\x80 which
    # causes a UnicodeDecodeError when trying to decode \xe2. Such broken
    # multibyte characters would need to be removed, otherwise the test will
    # result in an error.
    while not result:
        try:
            result = output.decode("utf-8")
        except UnicodeDecodeError as e:
            faulty_idx_start = int(e.start)
            faulty_idx_end = int(e.end)
            output = output[:faulty_idx_start] + output[faulty_idx_end:]

    if strip_ansi:
        result = ansi_clean(result)

    return result


def gdb_run_silent_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                       target: str = PATH_TO_DEFAULT_BINARY,
                       strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Disable the output and run entirely the `target` binary."""
    before = [*before, "gef config context.clear_screen False",
              "gef config context.layout '-code -stack'",
              "run"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_run_cmd_last_line(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                          target: str = PATH_TO_DEFAULT_BINARY,
                          strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_start_silent_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                         target: str = PATH_TO_DEFAULT_BINARY,
                         strip_ansi: bool = STRIP_ANSI_DEFAULT,
                         context: str = DEFAULT_CONTEXT) -> str:
    """Execute a command in GDB by starting an execution context. This command
    disables the `context` and sets a tbreak at the most convenient entry
    point."""
    before = [*before, "gef config context.clear_screen False",
              f"gef config context.layout '{context}'",
              "entry-break"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_start_silent_cmd_last_line(cmd: CommandType, before: CommandType = (),
                                   after: CommandType = (),
                                   target=PATH_TO_DEFAULT_BINARY,
                                   strip_ansi=STRIP_ANSI_DEFAULT) -> str:
    """Execute `gdb_start_silent_cmd()` and return only the last line of its output."""
    return gdb_start_silent_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_test_python_method(meth: str, before: str = "", after: str = "",
                           target: str = PATH_TO_DEFAULT_BINARY,
                           strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    brk = before + ";" if before else ""
    cmd = f"pi {brk}print({meth});{after}"
    return gdb_start_silent_cmd(cmd, target=target, strip_ansi=strip_ansi)


def include_for_architectures(valid_architectures: Iterable[str] = CI_VALID_ARCHITECTURES):
    def wrapper(f):
        def inner_f(*args, **kwargs):
            if ARCH in valid_architectures:
                f(*args, **kwargs)
            else:
                sys.stderr.write(f"SKIPPED for {ARCH}  ")
                sys.stderr.flush()
        return inner_f
    return wrapper


def exclude_for_architectures(invalid_architectures: Iterable[str] = ()):
    def wrapper(f):
        def inner_f(*args, **kwargs):
            if ARCH not in invalid_architectures:
                f(*args, **kwargs)
            else:
                sys.stderr.write(f"SKIPPED for {ARCH}  ")
                sys.stderr.flush()
        return inner_f
    return wrapper
