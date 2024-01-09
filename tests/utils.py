"""
Utility functions for testing
"""

import contextlib
import enum
import os
import pathlib
import platform
import re
import struct
import subprocess
import tempfile
import time
from typing import Iterable, List, Optional, Union
from urllib.request import urlopen


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
GEF_PATH = pathlib.Path(os.getenv("GEF_PATH", "gef.py")).absolute()
STRIP_ANSI_DEFAULT = True
GDBSERVER_DEFAULT_HOST = "localhost"
GDBSERVER_DEFAULT_PORT = 1234

GEF_RIGHT_ARROW = " → "

CommandType = Union[str, Iterable[str]]


ERROR_INACTIVE_SESSION_MESSAGE = "[*] No debugging session active\n"
WARNING_DEPRECATION_MESSAGE = "is deprecated and will be removed in a feature release."


class Color(enum.Enum):
    """Used to colorify terminal output."""

    NORMAL = "\x1b[0m"
    GRAY = "\x1b[1;38;5;240m"
    LIGHT_GRAY = "\x1b[0;37m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    PINK = "\x1b[35m"
    CYAN = "\x1b[36m"
    BOLD = "\x1b[1m"
    UNDERLINE = "\x1b[4m"
    UNDERLINE_OFF = "\x1b[24m"
    HIGHLIGHT = "\x1b[3m"
    HIGHLIGHT_OFF = "\x1b[23m"
    BLINK = "\x1b[5m"
    BLINK_OFF = "\x1b[25m"


def is_64b() -> bool:
    return ARCH in CI_VALID_ARCHITECTURES_64B


def is_32b() -> bool:
    return ARCH in CI_VALID_ARCHITECTURES_32B


def debug_target(name: str, extension: str = ".out") -> pathlib.Path:
    target = TMPDIR / f"{name}{extension}"
    if not target.exists():
        subprocess.run(["make", "-C", "tests/binaries", target.name])
        if not target.exists():
            raise FileNotFoundError(f"Could not find file '{target}'")
    return target


def start_gdbserver(
    exe: Union[str, pathlib.Path] = debug_target("default"),
    host: str = GDBSERVER_DEFAULT_HOST,
    port: int = GDBSERVER_DEFAULT_PORT,
) -> subprocess.Popen:
    """Start a gdbserver on the target binary.

    Args:
        exe (str, optional): the binary to execute. Defaults to debug_target("default").
        port (int, optional): the port to make gdbserver listen on. Defaults to 1234.

    Returns:
        subprocess.Popen: a Popen object for the gdbserver process.
    """
    return subprocess.Popen(
        ["gdbserver", f"{host}:{port}", exe],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_gdbserver(gdbserver: subprocess.Popen) -> None:
    """Stop the gdbserver and wait until it is terminated if it was
    still running. Needed to make the used port available again.

    Args:
        gdbserver (subprocess.Popen): the gdbserver process to stop.
    """
    if gdbserver.poll() is None:
        gdbserver.kill()
        gdbserver.wait()


@contextlib.contextmanager
def gdbserver_session(
    port: int = GDBSERVER_DEFAULT_PORT,
    host: str = GDBSERVER_DEFAULT_HOST,
    exe: Union[str, pathlib.Path] = debug_target("default"),
):
    sess = start_gdbserver(exe, host, port)
    try:
        time.sleep(1)  # forced delay to allow gdbserver to start listening
        yield sess
    finally:
        stop_gdbserver(sess)


def start_qemuuser(
    exe: Union[str, pathlib.Path] = debug_target("default"),
    port: int = GDBSERVER_DEFAULT_PORT,
) -> subprocess.Popen:
    return subprocess.Popen(
        ["qemu-x86_64", "-g", str(port), exe],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_qemuuser(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
        process.wait()


@contextlib.contextmanager
def qemuuser_session(*args, **kwargs):
    exe = kwargs.get("exe", "") or debug_target("default")
    port = kwargs.get("port", 0) or GDBSERVER_DEFAULT_PORT
    sess = start_qemuuser(exe, port)
    try:
        yield sess
    finally:
        stop_qemuuser(sess)


def find_symbol(binary: pathlib.Path, symbol: str) -> int:
    """Find a symbol by name in a ELF binary using `objdump`.
    The expect output syntax for `objdump` is:
    SYMBOL TABLE:
    0000000000000318 l    d  .interp        0000000000000000              .interp
    0000000000000338 l    d  .note.gnu.property     0000000000000000              .note.gnu.property
    0000000000000358 l    d  .note.gnu.build-id     0000000000000000              .note.gnu.build-id
    000000000000037c l    d  .note.ABI-tag  0000000000000000              .note.ABI-tag

    Args:
        binary (pathlib.Path): the ELF file to inspect
        symbol (str): the name of the symbol to find

    Returns:
        int the address/offset of the symbol

    Raises:
        KeyError if the symbol is not found
    """
    name = symbol.encode("utf8")
    for line in [
        x.strip().split()
        for x in subprocess.check_output(["objdump", "-t", binary]).splitlines()
        if len(x.strip())
    ]:
        if line[-1] == name:
            return int(line[0], 0x10)
    raise KeyError(f"`{symbol}` not found in {binary}")


def findlines(substring: str, buffer: str) -> List[str]:
    """Extract the lines from the buffer which contains the pattern
    `substring`

    Args:
        substring (str): the pattern to look for
        buffer (str): the buffer to look into

    Returns:
        List[str]
    """
    return [line.strip() for line in buffer.splitlines() if substring in line.strip()]


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


def u8(x: bytes) -> int:
    return struct.unpack("<B", x[:1])[0]


def u16(x: bytes) -> int:
    return struct.unpack("<H", x[:2])[0]


def u32(x: bytes) -> int:
    return struct.unpack("<I", x[:4])[0]


def u64(x: bytes) -> int:
    return struct.unpack("<Q", x[:8])[0]


def p8(x: int) -> bytes:
    return struct.pack("<B", x)


def p16(x: int) -> bytes:
    return struct.pack("<H", x)


def p32(x: int) -> bytes:
    return struct.pack("<I", x)


def p64(x: int) -> bytes:
    return struct.pack("<Q", x)
