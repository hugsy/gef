"""
Utility functions for testing
"""

import contextlib
import enum
import logging
import os
import pathlib
import platform
import struct
import subprocess
import tempfile
import time

from typing import Iterable, List, Optional, Union
from urllib.request import urlopen


def which(program: str) -> pathlib.Path:
    for path in os.environ["PATH"].split(os.pathsep):
        dirname = pathlib.Path(path)
        fpath = dirname / program
        if os.access(fpath, os.X_OK):
            return fpath
    raise FileNotFoundError(f"Missing file `{program}`")


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
GDBSERVER_BINARY = which("gdbserver")
assert GDBSERVER_BINARY.exists()

QEMU_USER_X64_BINARY = which("qemu-x86_64")
assert QEMU_USER_X64_BINARY.exists()

GEF_RIGHT_ARROW = " → "

CommandType = Union[str, Iterable[str]]


ERROR_INACTIVE_SESSION_MESSAGE = "[*] No debugging session active\n"
WARNING_DEPRECATION_MESSAGE = "is deprecated and will be removed in a feature release."

IN_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"

class Color(enum.Enum):
    """Used to colorify terminal output."""

    NORMAL          = "\001\033[0m\002"
    GRAY            = "\001\033[1;38;5;240m\002"
    LIGHT_GRAY      = "\001\033[0;37m\002"
    RED             = "\001\033[31m\002"
    GREEN           = "\001\033[32m\002"
    YELLOW          = "\001\033[33m\002"
    BLUE            = "\001\033[34m\002"
    PINK            = "\001\033[35m\002"
    CYAN            = "\001\033[36m\002"
    BOLD            = "\001\033[1m\002"
    UNDERLINE       = "\001\033[4m\002"
    UNDERLINE_OFF   = "\001\033[24m\002"
    HIGHLIGHT       = "\001\033[3m\002"
    HIGHLIGHT_OFF   = "\001\033[23m\002"
    BLINK           = "\001\033[5m\002"
    BLINK_OFF       = "\001\033[25m\002"


def is_glibc_ge(major, minor):
    ver = platform.libc_ver()
    if ver[0] == 'glibc':
        (glibc_major, glibc_minor, *glibc_patch) = list(map(int, ver[1].split('.')))
        return (glibc_major, glibc_minor) >= (major, minor)
    return False


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
    cmd = [GDBSERVER_BINARY, f"{host}:{port}", exe]
    logging.debug(f"Starting {cmd}")
    return subprocess.Popen(cmd)


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
        [QEMU_USER_X64_BINARY, "-g", str(port), exe],
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
    `included` is True, the result also includes the substring.

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
    `included` is True, the result also includes the substring.

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
