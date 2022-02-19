"""
Utility functions for testing
"""

import os
import pathlib
import platform
import re
import subprocess
import tempfile
import unittest
from urllib.request import urlopen
import warnings
import enum

from typing import Iterable, Union, List, Optional

TMPDIR = pathlib.Path(tempfile.gettempdir())
ARCH = (os.getenv("GEF_CI_ARCH") or platform.machine()).lower()
BIN_SH = pathlib.Path("/bin/sh")
CI_VALID_ARCHITECTURES_32B = ("i686", "armv7l")
CI_VALID_ARCHITECTURES_64B = ("x86_64", "aarch64", "mips64el", "ppc64le", "riscv64")
CI_VALID_ARCHITECTURES = CI_VALID_ARCHITECTURES_64B + CI_VALID_ARCHITECTURES_32B
COVERAGE_DIR = os.getenv("COVERAGE_DIR", "")
DEFAULT_CONTEXT = "-code -stack"
DEFAULT_TARGET = TMPDIR / "default.out"
GEF_DEFAULT_PROMPT = "gef➤  "
GEF_DEFAULT_TEMPDIR = "/tmp/gef"
GEF_PATH = pathlib.Path(os.getenv("GEF_PATH", "gef.py"))
STRIP_ANSI_DEFAULT = True


CommandType = Union[str, Iterable[str]]

class Color(enum.Enum):
    """Used to colorify terminal output."""
    NORMAL         = "\x1b[0m"
    GRAY           = "\x1b[1;38;5;240m"
    LIGHT_GRAY     = "\x1b[0;37m"
    RED            = "\x1b[31m"
    GREEN          = "\x1b[32m"
    YELLOW         = "\x1b[33m"
    BLUE           = "\x1b[34m"
    PINK           = "\x1b[35m"
    CYAN           = "\x1b[36m"
    BOLD           = "\x1b[1m"
    UNDERLINE      = "\x1b[4m"
    UNDERLINE_OFF  = "\x1b[24m"
    HIGHLIGHT      = "\x1b[3m"
    HIGHLIGHT_OFF  = "\x1b[23m"
    BLINK          = "\x1b[5m"
    BLINK_OFF      = "\x1b[25m"


class GdbAssertionError(AssertionError):
    pass


class GefUnitTestGeneric(unittest.TestCase):
    """Generic class for command testing, that defines all helpers"""

    @staticmethod
    def assertException(buf):
        """Assert that GEF raised an Exception."""
        if not ("Python Exception <" in buf
                or "Traceback" in buf
                or "'gdb.error'" in buf
                or "Exception raised" in buf
                or "failed to execute properly, reason:" in buf):
            raise GdbAssertionError("GDB Exception expected, not raised")

    @staticmethod
    def assertNoException(buf):
        """Assert that no Exception was raised from GEF."""
        if ("Python Exception <" in buf
                or "Traceback" in buf
                or "'gdb.error'" in buf
                or "Exception raised" in buf
                or "failed to execute properly, reason:" in buf):
            raise GdbAssertionError(f"Unexpected GDB Exception raised in {buf}")

        if "is deprecated and will be removed in a feature release." in buf:
            lines = [l for l in buf.splitlines()
                     if "is deprecated and will be removed in a feature release." in l]
            deprecated_api_names = {x.split()[1] for x in lines}
            warnings.warn(
                UserWarning(f"Use of deprecated API(s): {', '.join(deprecated_api_names)}")
            )

    @staticmethod
    def assertFailIfInactiveSession(buf):
        if "No debugging session active" not in buf:
            raise AssertionError("No debugging session inactive warning")


def is_64b() -> bool:
    return ARCH in CI_VALID_ARCHITECTURES_64B


def is_32b() -> bool:
    return ARCH in CI_VALID_ARCHITECTURES_32B


def ansi_clean(s: str) -> str:
    ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", s)


def _add_command(commands: CommandType) -> List[str]:
    if isinstance(commands, str):
        commands = [commands]
    return [_str for cmd in commands for _str in ["-ex", cmd]]


def gdb_run_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                target: pathlib.Path = DEFAULT_TARGET,
                strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = ["gdb", "-q", "-nx"]
    if COVERAGE_DIR:
        coverage_file = pathlib.Path(COVERAGE_DIR) / os.getenv("PYTEST_XDIST_WORKER", "gw0")
        command += _add_command([
            "pi from coverage import Coverage",
            f"pi cov = Coverage(data_file=\"{coverage_file}\","
            "auto_data=True, branch=True)",
            "pi cov.start()",
        ])
    command += _add_command([
        f"source {GEF_PATH}",
        "gef config gef.debug True",
    ])
    command += _add_command(before)
    command += _add_command(cmd)
    command += _add_command(after)
    if COVERAGE_DIR:
        command += _add_command(["pi cov.stop()", "pi cov.save()"])
    command += ["-ex", "quit", "--", str(target)]

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
        except UnicodeDecodeError as ude:
            faulty_idx_start = int(ude.start)
            faulty_idx_end = int(ude.end)
            output = output[:faulty_idx_start] + output[faulty_idx_end:]

    if strip_ansi:
        result = ansi_clean(result)

    return result


def gdb_run_silent_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                       target: pathlib.Path = DEFAULT_TARGET,
                       strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Disable the output and run entirely the `target` binary."""
    before = [*before, "gef config context.clear_screen False",
              "gef config context.layout '-code -stack'",
              "run"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_run_cmd_last_line(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                          target: pathlib.Path = DEFAULT_TARGET,
                          strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_start_silent_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                         target: pathlib.Path = DEFAULT_TARGET,
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
                                   target: pathlib.Path = DEFAULT_TARGET,
                                   strip_ansi=STRIP_ANSI_DEFAULT) -> str:
    """Execute `gdb_start_silent_cmd()` and return only the last line of its output."""
    return gdb_start_silent_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_test_python_method(meth: str, before: str = "", after: str = "",
                           target: pathlib.Path = DEFAULT_TARGET,
                           strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    brk = before + ";" if before else ""
    cmd = f"pi {brk}print({meth});{after}"
    return gdb_start_silent_cmd(cmd, target=target, strip_ansi=strip_ansi)


def gdb_time_python_method(meth: str, setup: str,
                           py_before: str = "", py_after: str = "",
                           before: CommandType = (), after: CommandType = (),
                           target: pathlib.Path = DEFAULT_TARGET,
                           strip_ansi: bool = STRIP_ANSI_DEFAULT, number: int = 1000) -> float:
    brk = py_before + ";" if py_before else ""
    cmd = f"""pi import timeit;{brk}print(timeit.timeit("{meth}", """\
          f"""setup="{setup}", number={number}));{py_after}"""
    lines = gdb_run_cmd(cmd, before=before, after=after,
                        target=target, strip_ansi=strip_ansi).splitlines()
    return float(lines[-1])


def _target(name: str, extension: str = ".out") -> pathlib.Path:
    target = TMPDIR / f"{name}{extension}"
    if not target.exists():
        raise FileNotFoundError(f"Could not find file '{target}'")
    return target


def start_gdbserver(exe: Union[str, pathlib.Path] = _target("default"),
                    port: int = 1234) -> subprocess.Popen:
    """Start a gdbserver on the target binary.

    Args:
        exe (str, optional): the binary to execute. Defaults to _target("default").
        port (int, optional): the port to make gdbserver listen on. Defaults to 1234.

    Returns:
        subprocess.Popen: a Popen object for the gdbserver process.
    """
    return subprocess.Popen(["gdbserver", f":{port}", exe],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_gdbserver(gdbserver: subprocess.Popen) -> None:
    """Stop the gdbserver and wait until it is terminated if it was
    still running. Needed to make the used port available again.

    Args:
        gdbserver (subprocess.Popen): the gdbserver process to stop.
    """
    if gdbserver.poll() is None:
        gdbserver.kill()
        gdbserver.wait()


def findlines(substring: str, buffer: str) -> List[str]:
    """Extract the lines from the buffer which contains the pattern
    `substring`

    Args:
        substring (str): the pattern to look for
        buffer (str): the buffer to look into

    Returns:
        List[str]
    """
    return [
        line.strip()
        for line in buffer.splitlines()
        if substring in line.strip()
    ]


def removeafter(substring: str, buffer: str, included: bool = False) -> str:
    """Returns a copy of `buffer` truncated after `substring` is found. If
    `included` is True, the result also includes the subtring.

    Args:
        substring (str)
        buffer (str)
        buffer (bool)

    Returns:
        str
    """
    idx = buffer.find(substring)
    if idx < 0:
        return buffer

    if not included:
        idx += len(substring)

    return buffer[:idx]


def removeuntil(substring: str, buffer: str, included: bool = False) -> str:
    """Returns a copy of `buffer` truncated until `substring` is found. If
    `included` is True, the result also includes the subtring.

    Args:
        substring (str)
        buffer (str)
        buffer (bool)

    Returns:
        str
    """
    idx = buffer.find(substring)
    if idx < 0:
        return buffer

    if not included:
        idx += len(substring)

    return buffer[idx:]



def download_file(url: str) -> Optional[bytes]:
    """Download a file from the internet.

    Args:
        url (str)

    Returns:
        Optional[bytes]
    """
    try:
        http = urlopen(url)
        return http.read() if http.getcode() == 200 else None
    except Exception:
        return None
