#######################################################################################
# GEF - Multi-Architecture GDB Enhanced Features for Exploiters & Reverse-Engineers
#
# by  @_hugsy_
#######################################################################################
#
# GEF is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC to
# make GDB cool again for exploit dev. It is aimed to be used mostly by exploit
# devs and reversers, to provides additional features to GDB using the Python
# API to assist during the process of dynamic analysis.
#
# GEF fully relies on GDB API and other Linux-specific sources of information
# (such as /proc/<pid>). As a consequence, some of the features might not work
# on custom or hardened systems such as GrSec.
#
# Since January 2020, GEF solely support GDB compiled with Python3 and was tested on
#   * x86-32 & x86-64
#   * arm v5,v6,v7
#   * aarch64 (armv8)
#   * mips & mips64
#   * powerpc & powerpc64
#   * sparc & sparc64(v9)
#
# For GEF with Python2 (only) support was moved to the GEF-Legacy
# (https://github.com/hugsy/gef-legacy)
#
# To start: in gdb, type `source /path/to/gef.py`
#
#######################################################################################
#
# gef is distributed under the MIT License (MIT)
# Copyright (c) 2013-2023 crazy rabbidz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import abc
import argparse
import ast
import atexit
import binascii
import codecs
import collections
import configparser
import ctypes
import enum
import functools
import hashlib
import importlib
import importlib.util
import inspect
import itertools
import os
import pathlib
import platform
import re
import shutil
import site
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import warnings
from functools import lru_cache
from io import StringIO, TextIOWrapper
from types import ModuleType
from typing import (Any, ByteString, Callable, Dict, Generator, Iterable,
                    Iterator, List, NoReturn, Optional, Sequence, Set, Tuple, Type,
                    Union)
from urllib.request import urlopen

GEF_DEFAULT_BRANCH                     = "main"
GEF_EXTRAS_DEFAULT_BRANCH              = "main"

def http_get(url: str) -> Optional[bytes]:
    """Basic HTTP wrapper for GET request. Return the body of the page if HTTP code is OK,
    otherwise return None."""
    try:
        http = urlopen(url)
        return http.read() if http.getcode() == 200 else None
    except Exception:
        return None


def update_gef(argv: List[str]) -> int:
    """Try to update `gef` to the latest version pushed on GitHub main branch.
    Return 0 on success, 1 on failure. """
    ver = GEF_DEFAULT_BRANCH
    latest_gef_data = http_get(f"https://raw.githubusercontent.com/hugsy/gef/{ver}/scripts/gef.sh")
    if not latest_gef_data:
        print("[-] Failed to get remote gef")
        return 1
    with tempfile.NamedTemporaryFile(suffix=".sh") as fd:
        fd.write(latest_gef_data)
        fd.flush()
        fpath = pathlib.Path(fd.name)
        return subprocess.run(["bash", fpath, ver], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode


try:
    import gdb  # type:ignore
except ImportError:
    # if out of gdb, the only action allowed is to update gef.py
    if len(sys.argv) >= 2 and sys.argv[1].lower() in ("--update", "--upgrade"):
        sys.exit(update_gef(sys.argv[2:]))
    print("[-] gef cannot run as standalone")
    sys.exit(0)


GDB_MIN_VERSION                        = (8, 0)
GDB_VERSION                            = tuple(map(int, re.search(r"(\d+)[^\d]+(\d+)", gdb.VERSION).groups()))
PYTHON_MIN_VERSION                     = (3, 6)
PYTHON_VERSION                         = sys.version_info[0:2]

DEFAULT_PAGE_ALIGN_SHIFT               = 12
DEFAULT_PAGE_SIZE                      = 1 << DEFAULT_PAGE_ALIGN_SHIFT

GEF_RC                                 = (pathlib.Path(os.getenv("GEF_RC", "")).absolute()
                                          if os.getenv("GEF_RC")
                                          else pathlib.Path().home() / ".gef.rc")
GEF_TEMP_DIR                           = os.path.join(tempfile.gettempdir(), "gef")
GEF_MAX_STRING_LENGTH                  = 50

LIBC_HEAP_MAIN_ARENA_DEFAULT_NAME      = "main_arena"
ANSI_SPLIT_RE                          = r"(\033\[[\d;]*m)"

LEFT_ARROW                             = " ← "
RIGHT_ARROW                            = " → "
DOWN_ARROW                             = "↳"
HORIZONTAL_LINE                        = "─"
VERTICAL_LINE                          = "│"
CROSS                                  = "✘ "
TICK                                   = "✓ "
BP_GLYPH                               = "●"
GEF_PROMPT                             = "gef➤  "
GEF_PROMPT_ON                          = f"\001\033[1;32m\002{GEF_PROMPT}\001\033[0m\002"
GEF_PROMPT_OFF                         = f"\001\033[1;31m\002{GEF_PROMPT}\001\033[0m\002"

PATTERN_LIBC_VERSION                   = re.compile(rb"glibc (\d+)\.(\d+)")

gef : "Gef"
__registered_commands__ : Set[Type["GenericCommand"]]                                        = set()
__registered_functions__ : Set[Type["GenericFunction"]]                                      = set()
__registered_architectures__ : Dict[Union["Elf.Abi", str], Type["Architecture"]]              = {}
__registered_file_formats__ : Set[ Type["FileFormat"] ]                                       = set()


def reset_all_caches() -> None:
    """Free all caches. If an object is cached, it will have a callable attribute `cache_clear`
    which will be invoked to purge the function cache."""

    for mod in dir(sys.modules["__main__"]):
        obj = getattr(sys.modules["__main__"], mod)
        if hasattr(obj, "cache_clear"):
            obj.cache_clear()

    gef.reset_caches()
    return


def reset() -> None:
    global gef

    arch = None
    if "gef" in locals().keys():
        reset_all_caches()
        arch = gef.arch
        del gef

    gef = Gef()
    gef.setup()

    if arch:
        gef.arch = arch
    return


def highlight_text(text: str) -> str:
    """
    Highlight text using `gef.ui.highlight_table` { match -> color } settings.

    If RegEx is enabled it will create a match group around all items in the
    `gef.ui.highlight_table` and wrap the specified color in the `gef.ui.highlight_table`
    around those matches.

    If RegEx is disabled, split by ANSI codes and 'colorify' each match found
    within the specified string.
    """
    global gef

    if not gef.ui.highlight_table:
        return text

    if gef.config["highlight.regex"]:
        for match, color in gef.ui.highlight_table.items():
            text = re.sub("(" + match + ")", Color.colorify("\\1", color), text)
        return text

    ansiSplit = re.split(ANSI_SPLIT_RE, text)

    for match, color in gef.ui.highlight_table.items():
        for index, val in enumerate(ansiSplit):
            found = val.find(match)
            if found > -1:
                ansiSplit[index] = val.replace(match, Color.colorify(match, color))
                break
        text = "".join(ansiSplit)
        ansiSplit = re.split(ANSI_SPLIT_RE, text)

    return "".join(ansiSplit)


def gef_print(*args: str, end="\n", sep=" ", **kwargs: Any) -> None:
    """Wrapper around print(), using string buffering feature."""
    parts = [highlight_text(a) for a in args]
    if buffer_output() and gef.ui.stream_buffer and not is_debug():
        gef.ui.stream_buffer.write(sep.join(parts) + end)
        return

    print(*parts, sep=sep, end=end, **kwargs)
    return


def bufferize(f: Callable) -> Callable:
    """Store the content to be printed for a function in memory, and flush it on function exit."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        global gef

        if gef.ui.stream_buffer:
            return f(*args, **kwargs)

        gef.ui.stream_buffer = StringIO()
        try:
            rv = f(*args, **kwargs)
        finally:
            redirect = gef.config["context.redirect"]
            if redirect.startswith("/dev/pts/"):
                if not gef.ui.redirect_fd:
                    # if the FD has never been open, open it
                    fd = open(redirect, "wt")
                    gef.ui.redirect_fd = fd
                elif redirect != gef.ui.redirect_fd.name:
                    # if the user has changed the redirect setting during runtime, update the state
                    gef.ui.redirect_fd.close()
                    fd = open(redirect, "wt")
                    gef.ui.redirect_fd = fd
                else:
                    # otherwise, keep using it
                    fd = gef.ui.redirect_fd
            else:
                fd = sys.stdout
                gef.ui.redirect_fd = None

            if gef.ui.redirect_fd and fd.closed:
                # if the tty was closed, revert back to stdout
                fd = sys.stdout
                gef.ui.redirect_fd = None
                gef.config["context.redirect"] = ""

            fd.write(gef.ui.stream_buffer.getvalue())
            fd.flush()
            gef.ui.stream_buffer = None
        return rv

    return wrapper


#
# Helpers
#

def p8(x: int, s: bool = False, e: Optional["Endianness"] = None) -> bytes:
    """Pack one byte respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.pack(f"{endian}B", x) if not s else struct.pack(f"{endian:s}b", x)


def p16(x: int, s: bool = False, e: Optional["Endianness"] = None) -> bytes:
    """Pack one word respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.pack(f"{endian}H", x) if not s else struct.pack(f"{endian:s}h", x)


def p32(x: int, s: bool = False, e: Optional["Endianness"] = None) -> bytes:
    """Pack one dword respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.pack(f"{endian}I", x) if not s else struct.pack(f"{endian:s}i", x)


def p64(x: int, s: bool = False, e: Optional["Endianness"] = None) -> bytes:
    """Pack one qword respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.pack(f"{endian}Q", x) if not s else struct.pack(f"{endian:s}q", x)


def u8(x: bytes, s: bool = False, e: Optional["Endianness"] = None) -> int:
    """Unpack one byte respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.unpack(f"{endian}B", x)[0] if not s else struct.unpack(f"{endian:s}b", x)[0]


def u16(x: bytes, s: bool = False, e: Optional["Endianness"] = None) -> int:
    """Unpack one word respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.unpack(f"{endian}H", x)[0] if not s else struct.unpack(f"{endian:s}h", x)[0]


def u32(x: bytes, s: bool = False, e: Optional["Endianness"] = None) -> int:
    """Unpack one dword respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.unpack(f"{endian}I", x)[0] if not s else struct.unpack(f"{endian:s}i", x)[0]


def u64(x: bytes, s: bool = False, e: Optional["Endianness"] = None) -> int:
    """Unpack one qword respecting the current architecture endianness."""
    endian = e or gef.arch.endianness
    return struct.unpack(f"{endian}Q", x)[0] if not s else struct.unpack(f"{endian:s}q", x)[0]


def is_ascii_string(address: int) -> bool:
    """Helper function to determine if the buffer pointed by `address` is an ASCII string (in GDB)"""
    try:
        return gef.memory.read_ascii_string(address) is not None
    except Exception:
        return False


def is_alive() -> bool:
    """Check if GDB is running."""
    try:
        return gdb.selected_inferior().pid > 0
    except Exception:
        return False


def calling_function() -> Optional[str]:
    """Return the name of the calling function"""
    try:
        stack_info = traceback.extract_stack()[-3]
        return stack_info.name
    except:
        return None


#
# Decorators
#
def only_if_gdb_running(f: Callable) -> Callable:
    """Decorator wrapper to check if GDB is running."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if is_alive():
            return f(*args, **kwargs)
        else:
            warn("No debugging session active")

    return wrapper


def only_if_gdb_target_local(f: Callable) -> Callable:
    """Decorator wrapper to check if GDB is running locally (target not remote)."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not is_remote_debug():
            return f(*args, **kwargs)
        else:
            warn("This command cannot work for remote sessions.")

    return wrapper


def deprecated(solution: str = "") -> Callable:
    """Decorator to add a warning when a command is obsolete and will be removed."""
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            caller = inspect.stack()[1]
            caller_file = pathlib.Path(caller.filename)
            caller_loc = caller.lineno
            msg = f"{caller_file.name}:L{caller_loc} '{f.__name__}' is deprecated and will be removed in a feature release. "
            if not gef:
                print(msg)
            elif gef.config["gef.show_deprecation_warnings"] is True:
                if solution:
                    msg += solution
                warn(msg)
            return f(*args, **kwargs)

        if not wrapper.__doc__:
            wrapper.__doc__ = ""
        wrapper.__doc__ += f"\r\n`{f.__name__}` is **DEPRECATED** and will be removed in the future.\r\n{solution}"
        return wrapper
    return decorator


def experimental_feature(f: Callable) -> Callable:
    """Decorator to add a warning when a feature is experimental."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        warn("This feature is under development, expect bugs and unstability...")
        return f(*args, **kwargs)

    return wrapper


def only_if_events_supported(event_type: str) -> Callable:
    """Checks if GDB supports events without crashing."""
    def wrap(f: Callable) -> Callable:
        def wrapped_f(*args: Any, **kwargs: Any) -> Any:
            if getattr(gdb, "events") and getattr(gdb.events, event_type):
                return f(*args, **kwargs)
            warn("GDB events cannot be set")
        return wrapped_f
    return wrap


class classproperty(property):
    """Make the attribute a `classproperty`."""
    def __get__(self, cls, owner):
        return classmethod(self.fget).__get__(None, owner)()


def FakeExit(*args: Any, **kwargs: Any) -> NoReturn:
    raise RuntimeWarning


sys.exit = FakeExit


def parse_arguments(required_arguments: Dict[Union[str, Tuple[str, str]], Any],
                    optional_arguments: Dict[Union[str, Tuple[str, str]], Any]) -> Callable:
    """Argument parsing decorator."""

    def int_wrapper(x: str) -> int: return int(x, 0)

    def decorator(f: Callable) -> Optional[Callable]:
        def wrapper(*args: Any, **kwargs: Any) -> Callable:
            parser = argparse.ArgumentParser(prog=args[0]._cmdline_, add_help=True)
            for argname in required_arguments:
                argvalue = required_arguments[argname]
                argtype = type(argvalue)
                if argtype is int:
                    argtype = int_wrapper

                argname_is_list = not isinstance(argname, str)
                assert not argname_is_list and isinstance(argname, str)
                if not argname_is_list and argname.startswith("-"):
                    # optional args
                    if argtype is bool:
                        parser.add_argument(argname, action="store_true" if argvalue else "store_false")
                    else:
                        parser.add_argument(argname, type=argtype, required=True, default=argvalue)
                else:
                    if argtype in (list, tuple):
                        nargs = "*"
                        argtype = type(argvalue[0])
                    else:
                        nargs = "?"
                    # positional args
                    parser.add_argument(argname, type=argtype, default=argvalue, nargs=nargs)

            for argname in optional_arguments:
                if isinstance(argname, str) and not argname.startswith("-"):
                    # refuse positional arguments
                    continue
                argvalue = optional_arguments[argname]
                argtype = type(argvalue)
                if isinstance(argname, str):
                    argname = [argname,]
                if argtype is int:
                    argtype = int_wrapper
                if argtype is bool:
                    parser.add_argument(*argname, action="store_true" if argvalue else "store_false")
                else:
                    parser.add_argument(*argname, type=argtype, default=argvalue)

            parsed_args = parser.parse_args(*(args[1:]))
            kwargs["arguments"] = parsed_args
            return f(*args, **kwargs)
        return wrapper
    return decorator


class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "light_gray"     : "\033[0;37m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "cyan"           : "\033[36m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    @staticmethod
    def redify(msg: str) -> str:        return Color.colorify(msg, "red")
    @staticmethod
    def greenify(msg: str) -> str:      return Color.colorify(msg, "green")
    @staticmethod
    def blueify(msg: str) -> str:       return Color.colorify(msg, "blue")
    @staticmethod
    def yellowify(msg: str) -> str:     return Color.colorify(msg, "yellow")
    @staticmethod
    def grayify(msg: str) -> str:       return Color.colorify(msg, "gray")
    @staticmethod
    def light_grayify(msg: str) -> str: return Color.colorify(msg, "light_gray")
    @staticmethod
    def pinkify(msg: str) -> str:       return Color.colorify(msg, "pink")
    @staticmethod
    def cyanify(msg: str) -> str:       return Color.colorify(msg, "cyan")
    @staticmethod
    def boldify(msg: str) -> str:       return Color.colorify(msg, "bold")
    @staticmethod
    def underlinify(msg: str) -> str:   return Color.colorify(msg, "underline")
    @staticmethod
    def highlightify(msg: str) -> str:  return Color.colorify(msg, "highlight")
    @staticmethod
    def blinkify(msg: str) -> str:      return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text: str, attrs: str) -> str:
        """Color text according to the given attributes."""
        if gef.config["gef.disable_color"] is True: return text

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg:   msg.append(colors["highlight_off"])
        if colors["underline"] in msg:   msg.append(colors["underline_off"])
        if colors["blink"] in msg:       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


class Address:
    """GEF representation of memory addresses."""
    def __init__(self, **kwargs: Any) -> None:
        self.value: int = kwargs.get("value", 0)
        self.section: "Section" = kwargs.get("section", None)
        self.info: "Zone" = kwargs.get("info", None)
        return

    def __str__(self) -> str:
        value = format_address(self.value)
        code_color = gef.config["theme.address_code"]
        stack_color = gef.config["theme.address_stack"]
        heap_color = gef.config["theme.address_heap"]
        if self.is_in_text_segment():
            return Color.colorify(value, code_color)
        if self.is_in_heap_segment():
            return Color.colorify(value, heap_color)
        if self.is_in_stack_segment():
            return Color.colorify(value, stack_color)
        return value

    def __int__(self) -> int:
        return self.value

    def is_in_text_segment(self) -> bool:
        return (hasattr(self.info, "name") and ".text" in self.info.name) or \
            (hasattr(self.section, "path") and get_filepath() == self.section.path and self.section.is_executable())

    def is_in_stack_segment(self) -> bool:
        return hasattr(self.section, "path") and "[stack]" == self.section.path

    def is_in_heap_segment(self) -> bool:
        return hasattr(self.section, "path") and "[heap]" == self.section.path

    def dereference(self) -> Optional[int]:
        addr = align_address(int(self.value))
        derefed = dereference(addr)
        return None if derefed is None else int(derefed)

    @property
    def valid(self) -> bool:
        return any(map(lambda x: x.page_start <= self.value < x.page_end, gef.memory.maps))


class Permission(enum.Flag):
    """GEF representation of Linux permission."""
    NONE      = 0
    EXECUTE   = 1
    WRITE     = 2
    READ      = 4
    ALL       = 7

    def __str__(self) -> str:
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    @classmethod
    def from_info_sections(cls, *args: str) -> "Permission":
        perm = cls(0)
        for arg in args:
            if "READONLY" in arg: perm |= Permission.READ
            if "DATA" in arg: perm |= Permission.WRITE
            if "CODE" in arg: perm |= Permission.EXECUTE
        return perm

    @classmethod
    def from_process_maps(cls, perm_str: str) -> "Permission":
        perm = cls(0)
        if perm_str[0] == "r": perm |= Permission.READ
        if perm_str[1] == "w": perm |= Permission.WRITE
        if perm_str[2] == "x": perm |= Permission.EXECUTE
        return perm

    @classmethod
    def from_info_mem(cls, perm_str: str) -> "Permission":
        perm = cls(0)
        # perm_str[0] shows if this is a user page, which
        # we don't track
        if perm_str[1] == "r": perm |= Permission.READ
        if perm_str[2] == "w": perm |= Permission.WRITE
        return perm


class Section:
    """GEF representation of process memory sections."""

    def __init__(self, **kwargs: Any) -> None:
        self.page_start: int = kwargs.get("page_start", 0)
        self.page_end: int = kwargs.get("page_end", 0)
        self.offset: int = kwargs.get("offset", 0)
        self.permission: Permission = kwargs.get("permission", Permission(0))
        self.inode: int = kwargs.get("inode", 0)
        self.path: str = kwargs.get("path", "")
        return

    def is_readable(self) -> bool:
        return (self.permission & Permission.READ) != 0

    def is_writable(self) -> bool:
        return (self.permission & Permission.WRITE) != 0

    def is_executable(self) -> bool:
        return (self.permission & Permission.EXECUTE) != 0

    @property
    def size(self) -> int:
        if self.page_end is None or self.page_start is None:
            return -1
        return self.page_end - self.page_start

    @property
    def realpath(self) -> str:
        # when in a `gef-remote` session, realpath returns the path to the binary on the local disk, not remote
        return self.path if gef.session.remote is None else f"/tmp/gef/{gef.session.remote:d}/{self.path}"

    def __str__(self) -> str:
        return (f"Section(page_start={self.page_start:#x}, page_end={self.page_end:#x}, "
                f"permissions={self.permission!s})")


Zone = collections.namedtuple("Zone", ["name", "zone_start", "zone_end", "filename"])


class Endianness(enum.Enum):
    LITTLE_ENDIAN     = 1
    BIG_ENDIAN        = 2

    def __str__(self) -> str:
        return "<" if self == Endianness.LITTLE_ENDIAN else ">"

    def __repr__(self) -> str:
        return self.name

    def __int__(self) -> int:
        return self.value


class FileFormatSection:
    misc: Any


class FileFormat:
    name: str
    path: pathlib.Path
    entry_point: int
    checksec: Dict[str, bool]
    sections: List[FileFormatSection]

    def __init__(self, path: Union[str, pathlib.Path]) -> None:
        raise NotImplemented

    def __init_subclass__(cls: Type["FileFormat"], **kwargs):
        global __registered_file_formats__
        super().__init_subclass__(**kwargs)
        required_attributes = ("name", "entry_point", "is_valid", "checksec",)
        for attr in required_attributes:
            if not hasattr(cls, attr):
                raise NotImplementedError(f"File format '{cls.__name__}' is invalid: missing attribute '{attr}'")
        __registered_file_formats__.add(cls)
        return

    @classmethod
    def is_valid(cls, path: pathlib.Path) -> bool:
        raise NotImplemented

    def __str__(self) -> str:
        return f"{self.name}('{self.path.absolute()}', entry @ {self.entry_point:#x})"


class Elf(FileFormat):
    """Basic ELF parsing.
    Ref:
    - http://www.skyfree.org/linux/references/ELF_Format.pdf
    - https://refspecs.linuxfoundation.org/elf/elfspec_ppc.pdf
    - https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html
    """
    class Class(enum.Enum):
        ELF_32_BITS       = 0x01
        ELF_64_BITS       = 0x02

    ELF_MAGIC         = 0x7f454c46

    class Abi(enum.Enum):
        X86_64            = 0x3e
        X86_32            = 0x03
        ARM               = 0x28
        MIPS              = 0x08
        POWERPC           = 0x14
        POWERPC64         = 0x15
        SPARC             = 0x02
        SPARC64           = 0x2b
        AARCH64           = 0xb7
        RISCV             = 0xf3
        IA64              = 0x32
        M68K              = 0x04

    class Type(enum.Enum):
        ET_RELOC          = 1
        ET_EXEC           = 2
        ET_DYN            = 3
        ET_CORE           = 4

    class OsAbi(enum.Enum):
        SYSTEMV     = 0x00
        HPUX        = 0x01
        NETBSD      = 0x02
        LINUX       = 0x03
        SOLARIS     = 0x06
        AIX         = 0x07
        IRIX        = 0x08
        FREEBSD     = 0x09
        OPENBSD     = 0x0C

    e_magic: int                = ELF_MAGIC
    e_class: "Elf.Class"        = Class.ELF_32_BITS
    e_endianness: Endianness    = Endianness.LITTLE_ENDIAN
    e_eiversion: int
    e_osabi: "Elf.OsAbi"
    e_abiversion: int
    e_pad: bytes
    e_type: "Elf.Type"          = Type.ET_EXEC
    e_machine: Abi              = Abi.X86_32
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    path: pathlib.Path
    phdrs : List["Phdr"]
    shdrs : List["Shdr"]
    name: str = "ELF"

    __checksec : Dict[str, bool]

    def __init__(self, path: Union[str, pathlib.Path]) -> None:
        """Instantiate an ELF object. A valid ELF must be provided, or an exception will be thrown."""

        if isinstance(path, str):
            self.path = pathlib.Path(path).expanduser()
        elif isinstance(path, pathlib.Path):
            self.path = path
        else:
            raise TypeError

        if not self.path.exists():
            raise FileNotFoundError(f"'{self.path}' not found/readable, most gef features will not work")

        self.__checksec = {}

        with self.path.open("rb") as self.fd:
            # off 0x0
            self.e_magic, e_class, e_endianness, self.e_eiversion = self.read_and_unpack(">IBBB")
            if self.e_magic != Elf.ELF_MAGIC:
                # The ELF is corrupted, GDB won't handle it, no point going further
                raise RuntimeError("Not a valid ELF file (magic)")

            self.e_class, self.e_endianness = Elf.Class(e_class), Endianness(e_endianness)

            if self.e_endianness != gef.arch.endianness:
                warn("Unexpected endianness for architecture")

            endian = self.e_endianness

            # off 0x7
            e_osabi, self.e_abiversion = self.read_and_unpack(f"{endian}BB")
            self.e_osabi = Elf.OsAbi(e_osabi)

            # off 0x9
            self.e_pad = self.read(7)

            # off 0x10
            e_type, e_machine, self.e_version = self.read_and_unpack(f"{endian}HHI")
            self.e_type, self.e_machine = Elf.Type(e_type), Elf.Abi(e_machine)

            # off 0x18
            if self.e_class == Elf.Class.ELF_64_BITS:
                self.e_entry, self.e_phoff, self.e_shoff = self.read_and_unpack(f"{endian}QQQ")
            else:
                self.e_entry, self.e_phoff, self.e_shoff = self.read_and_unpack(f"{endian}III")

            self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum = self.read_and_unpack(f"{endian}IHHH")
            self.e_shentsize, self.e_shnum, self.e_shstrndx = self.read_and_unpack(f"{endian}HHH")

            self.phdrs = []
            for i in range(self.e_phnum):
                self.phdrs.append(Phdr(self, self.e_phoff + self.e_phentsize * i))

            self.shdrs = []
            for i in range(self.e_shnum):
                self.shdrs.append(Shdr(self, self.e_shoff + self.e_shentsize * i))
        return

    def read(self, size: int) -> bytes:
        return self.fd.read(size)

    def read_and_unpack(self, fmt: str) -> Tuple[Any, ...]:
        size = struct.calcsize(fmt)
        data = self.fd.read(size)
        return struct.unpack(fmt, data)

    def seek(self, off: int) -> None:
        self.fd.seek(off, 0)

    def __str__(self) -> str:
        return f"ELF('{self.path.absolute()}', {self.e_class.name}, {self.e_machine.name})"

    def __repr__(self) -> str:
        return f"ELF('{self.path.absolute()}', {self.e_class.name}, {self.e_machine.name})"

    @property
    def entry_point(self) -> int:
        return self.e_entry

    @classmethod
    def is_valid(cls, path: pathlib.Path) -> bool:
        return u32(path.open("rb").read(4), e = Endianness.BIG_ENDIAN) == Elf.ELF_MAGIC

    @property
    def checksec(self) -> Dict[str, bool]:
        """Check the security property of the ELF binary. The following properties are:
        - Canary
        - NX
        - PIE
        - Fortify
        - Partial/Full RelRO.
        Return a dict() with the different keys mentioned above, and the boolean
        associated whether the protection was found."""
        if not self.__checksec:
            def __check_security_property(opt: str, filename: str, pattern: str) -> bool:
                cmd   = [readelf,]
                cmd  += opt.split()
                cmd  += [filename,]
                lines = gef_execute_external(cmd, as_list=True)
                for line in lines:
                    if re.search(pattern, line):
                        return True
                return False

            abspath = str(self.path.absolute())
            readelf = gef.session.constants["readelf"]
            self.__checksec["Canary"] = __check_security_property("-rs", abspath, r"__stack_chk_fail") is True
            has_gnu_stack = __check_security_property("-W -l", abspath, r"GNU_STACK") is True
            if has_gnu_stack:
                self.__checksec["NX"] = __check_security_property("-W -l", abspath, r"GNU_STACK.*RWE") is False
            else:
                self.__checksec["NX"] = False
            self.__checksec["PIE"] = __check_security_property("-h", abspath, r":.*EXEC") is False
            self.__checksec["Fortify"] = __check_security_property("-s", abspath, r"_chk@GLIBC") is True
            self.__checksec["Partial RelRO"] = __check_security_property("-l", abspath, r"GNU_RELRO") is True
            self.__checksec["Full RelRO"] = self.__checksec["Partial RelRO"] and __check_security_property("-d", abspath, r"BIND_NOW") is True
        return self.__checksec

    @classproperty
    @deprecated("use `Elf.Abi.X86_64`")
    def X86_64(cls) -> int: return Elf.Abi.X86_64.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.X86_32`")
    def X86_32(cls) -> int : return Elf.Abi.X86_32.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.ARM`")
    def ARM(cls) -> int : return Elf.Abi.ARM.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.MIPS`")
    def MIPS(cls) -> int : return Elf.Abi.MIPS.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.POWERPC`")
    def POWERPC(cls) -> int : return Elf.Abi.POWERPC.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.POWERPC64`")
    def POWERPC64(cls) -> int : return Elf.Abi.POWERPC64.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.SPARC`")
    def SPARC(cls) -> int : return Elf.Abi.SPARC.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.SPARC64`")
    def SPARC64(cls) -> int : return Elf.Abi.SPARC64.value # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.AARCH64`")
    def AARCH64(cls) -> int : return Elf.Abi.AARCH64.value  # pylint: disable=no-self-argument

    @classproperty
    @deprecated("use `Elf.Abi.RISCV`")
    def RISCV(cls) -> int : return Elf.Abi.RISCV.value # pylint: disable=no-self-argument


class Phdr:
    class Type(enum.IntEnum):
        PT_NULL         = 0
        PT_LOAD         = 1
        PT_DYNAMIC      = 2
        PT_INTERP       = 3
        PT_NOTE         = 4
        PT_SHLIB        = 5
        PT_PHDR         = 6
        PT_TLS          = 7
        PT_LOOS         = 0x60000000
        PT_GNU_EH_FRAME = 0x6474e550
        PT_GNU_STACK    = 0x6474e551
        PT_GNU_RELRO    = 0x6474e552
        PT_GNU_PROPERTY = 0x6474e553
        PT_LOSUNW       = 0x6ffffffa
        PT_SUNWBSS      = 0x6ffffffa
        PT_SUNWSTACK    = 0x6ffffffb
        PT_HISUNW       = PT_HIOS         = 0x6fffffff
        PT_LOPROC       = 0x70000000
        PT_ARM_EIDX     = 0x70000001
        PT_MIPS_ABIFLAGS= 0x70000003
        PT_HIPROC       = 0x7fffffff
        UNKNOWN_PHDR    = 0xffffffff

        @classmethod
        def _missing_(cls, _:int) -> Type:
            return cls.UNKNOWN_PHDR

    class Flags(enum.IntFlag):
        PF_X            = 1
        PF_W            = 2
        PF_R            = 4

    p_type: "Phdr.Type"
    p_flags: "Phdr.Flags"
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    def __init__(self, elf: Elf, off: int) -> None:
        if not elf:
            return
        elf.seek(off)
        self.offset = off
        endian = elf.e_endianness
        if elf.e_class == Elf.Class.ELF_64_BITS:
            p_type, p_flags, self.p_offset = elf.read_and_unpack(f"{endian}IIQ")
            self.p_vaddr, self.p_paddr = elf.read_and_unpack(f"{endian}QQ")
            self.p_filesz, self.p_memsz, self.p_align = elf.read_and_unpack(f"{endian}QQQ")
        else:
            p_type, self.p_offset = elf.read_and_unpack(f"{endian}II")
            self.p_vaddr, self.p_paddr = elf.read_and_unpack(f"{endian}II")
            self.p_filesz, self.p_memsz, p_flags, self.p_align = elf.read_and_unpack(f"{endian}IIII")

        self.p_type, self.p_flags = Phdr.Type(p_type), Phdr.Flags(p_flags)
        return

    def __str__(self) -> str:
        return (f"Phdr(offset={self.offset}, type={self.p_type.name}, flags={self.p_flags.name}, "
	            f"vaddr={self.p_vaddr}, paddr={self.p_paddr}, filesz={self.p_filesz}, "
	            f"memsz={self.p_memsz}, align={self.p_align})")


class Shdr:
    class Type(enum.IntEnum):
        SHT_NULL             = 0
        SHT_PROGBITS         = 1
        SHT_SYMTAB           = 2
        SHT_STRTAB           = 3
        SHT_RELA             = 4
        SHT_HASH             = 5
        SHT_DYNAMIC          = 6
        SHT_NOTE             = 7
        SHT_NOBITS           = 8
        SHT_REL              = 9
        SHT_SHLIB            = 10
        SHT_DYNSYM           = 11
        SHT_NUM	             = 12
        SHT_INIT_ARRAY       = 14
        SHT_FINI_ARRAY       = 15
        SHT_PREINIT_ARRAY    = 16
        SHT_GROUP            = 17
        SHT_SYMTAB_SHNDX     = 18
        SHT_LOOS             = 0x60000000
        SHT_GNU_ATTRIBUTES   = 0x6ffffff5
        SHT_GNU_HASH         = 0x6ffffff6
        SHT_GNU_LIBLIST      = 0x6ffffff7
        SHT_CHECKSUM         = 0x6ffffff8
        SHT_LOSUNW           = 0x6ffffffa
        SHT_SUNW_move        = 0x6ffffffa
        SHT_SUNW_COMDAT      = 0x6ffffffb
        SHT_SUNW_syminfo     = 0x6ffffffc
        SHT_GNU_verdef       = 0x6ffffffd
        SHT_GNU_verneed      = 0x6ffffffe
        SHT_GNU_versym       = 0x6fffffff
        SHT_LOPROC           = 0x70000000
        SHT_ARM_EXIDX        = 0x70000001
        SHT_X86_64_UNWIND    = 0x70000001
        SHT_ARM_ATTRIBUTES   = 0x70000003
        SHT_MIPS_OPTIONS     = 0x7000000d
        DT_MIPS_INTERFACE    = 0x7000002a
        SHT_HIPROC           = 0x7fffffff
        SHT_LOUSER           = 0x80000000
        SHT_HIUSER           = 0x8fffffff
        UNKNOWN_SHDR         = 0xffffffff

        @classmethod
        def _missing_(cls, _:int) -> Type:
            return cls.UNKNOWN_SHDR

    class Flags(enum.IntFlag):
        WRITE            = 1
        ALLOC            = 2
        EXECINSTR        = 4
        MERGE            = 0x10
        STRINGS          = 0x20
        INFO_LINK        = 0x40
        LINK_ORDER       = 0x80
        OS_NONCONFORMING = 0x100
        GROUP            = 0x200
        TLS              = 0x400
        COMPRESSED       = 0x800
        RELA_LIVEPATCH   = 0x00100000
        RO_AFTER_INIT    = 0x00200000
        ORDERED          = 0x40000000
        EXCLUDE          = 0x80000000
        UNKNOWN_FLAG     = 0xffffffff

        @classmethod
        def _missing_(cls, _:int):
            return cls.UNKNOWN_FLAG

    sh_name: int
    sh_type: "Shdr.Type"
    sh_flags: "Shdr.Flags"
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int
    name: str

    def __init__(self, elf: Optional[Elf], off: int) -> None:
        if elf is None:
            return
        elf.seek(off)
        endian = elf.e_endianness
        if elf.e_class == Elf.Class.ELF_64_BITS:
            self.sh_name, sh_type, sh_flags = elf.read_and_unpack(f"{endian}IIQ")
            self.sh_addr, self.sh_offset = elf.read_and_unpack(f"{endian}QQ")
            self.sh_size, self.sh_link, self.sh_info = elf.read_and_unpack(f"{endian}QII")
            self.sh_addralign, self.sh_entsize = elf.read_and_unpack(f"{endian}QQ")
        else:
            self.sh_name, sh_type, sh_flags = elf.read_and_unpack(f"{endian}III")
            self.sh_addr, self.sh_offset = elf.read_and_unpack(f"{endian}II")
            self.sh_size, self.sh_link, self.sh_info = elf.read_and_unpack(f"{endian}III")
            self.sh_addralign, self.sh_entsize = elf.read_and_unpack(f"{endian}II")

        self.sh_type = Shdr.Type(sh_type)
        self.sh_flags = Shdr.Flags(sh_flags)
        stroff = elf.e_shoff + elf.e_shentsize * elf.e_shstrndx

        if elf.e_class == Elf.Class.ELF_64_BITS:
            elf.seek(stroff + 16 + 8)
            offset = u64(elf.read(8))
        else:
            elf.seek(stroff + 12 + 4)
            offset = u32(elf.read(4))
        elf.seek(offset + self.sh_name)
        self.name = ""
        while True:
            c = u8(elf.read(1))
            if c == 0:
                break
            self.name += chr(c)
        return

    def __str__(self) -> str:
        return (f"Shdr(name={self.name}, type={self.sh_type.name}, flags={self.sh_flags.name}, "
	            f"addr={self.sh_addr:#x}, offset={self.sh_offset}, size={self.sh_size}, link={self.sh_link}, "
	            f"info={self.sh_info}, addralign={self.sh_addralign}, entsize={self.sh_entsize})")


class Instruction:
    """GEF representation of a CPU instruction."""

    def __init__(self, address: int, location: str, mnemo: str, operands: List[str], opcodes: bytes) -> None:
        self.address, self.location, self.mnemonic, self.operands, self.opcodes = \
            address, location, mnemo, operands, opcodes
        return

    # Allow formatting an instruction with {:o} to show opcodes.
    # The number of bytes to display can be configured, e.g. {:4o} to only show 4 bytes of the opcodes
    def __format__(self, format_spec: str) -> str:
        if len(format_spec) == 0 or format_spec[-1] != "o":
            return str(self)

        if format_spec == "o":
            opcodes_len = len(self.opcodes)
        else:
            opcodes_len = int(format_spec[:-1])

        opcodes_text = "".join(f"{b:02x}" for b in self.opcodes[:opcodes_len])
        if opcodes_len < len(self.opcodes):
            opcodes_text += "..."
        return (f"{self.address:#10x} {opcodes_text:{opcodes_len * 2 + 3:d}s} {self.location:16} "
                f"{self.mnemonic:6} {', '.join(self.operands)}")

    def __str__(self) -> str:
        return f"{self.address:#10x} {self.location:16} {self.mnemonic:6} {', '.join(self.operands)}"

    def is_valid(self) -> bool:
        return "(bad)" not in self.mnemonic

    def size(self) -> int:
        return len(self.opcodes)

    def next(self) -> "Instruction":
        address = self.address + self.size()
        return gef_get_instruction_at(address)


@deprecated("Use GefHeapManager.find_main_arena_addr()")
def search_for_main_arena() -> int:
    return GefHeapManager.find_main_arena_addr()

class GlibcHeapInfo:
    """Glibc heap_info struct"""

    @staticmethod
    def heap_info_t() -> Type[ctypes.Structure]:
        assert gef.libc.version
        class heap_info_cls(ctypes.Structure):
            pass
        pointer = ctypes.c_uint64 if gef.arch.ptrsize == 8 else ctypes.c_uint32
        pad_size = -5 * gef.arch.ptrsize & (gef.heap.malloc_alignment - 1)
        fields = [
            ("ar_ptr", ctypes.POINTER(GlibcArena.malloc_state_t())),
            ("prev", ctypes.POINTER(heap_info_cls)),
            ("size", pointer)
        ]
        if gef.libc.version >= (2, 5):
            fields += [
                ("mprotect_size", pointer)
            ]
            pad_size = -6 * gef.arch.ptrsize & (gef.heap.malloc_alignment - 1)
        if gef.libc.version >= (2, 34):
            fields += [
                ("pagesize", pointer)
            ]
            pad_size = -3 * gef.arch.ptrsize & (gef.heap.malloc_alignment - 1)
        fields += [
            ("pad", ctypes.c_uint8*pad_size)
        ]
        heap_info_cls._fields_ = fields
        return heap_info_cls

    def __init__(self, addr: Union[str, int]) -> None:
        self.__address : int = parse_address(f"&{addr}") if isinstance(addr, str) else addr
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(GlibcHeapInfo.heap_info_t())
        self._data = gef.memory.read(self.__address, ctypes.sizeof(GlibcHeapInfo.heap_info_t()))
        self._heap_info = GlibcHeapInfo.heap_info_t().from_buffer_copy(self._data)
        return

    def __getattr__(self, item: Any) -> Any:
        if item in dir(self._heap_info):
            return ctypes.cast(getattr(self._heap_info, item), ctypes.c_void_p).value
        return getattr(self, item)

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def heap_start(self) -> int:
        # check special case: first heap of non-main-arena
        if self.ar_ptr - self.address < 0x60:
            # the first heap of a non-main-arena starts with a `heap_info`
            # struct, which should fit easily into 0x60 bytes throughout
            # all architectures and glibc versions. If this check succeeds
            # then we are currently looking at such a "first heap"
            arena = GlibcArena(f"*{self.ar_ptr:#x}")
            heap_addr = arena.heap_addr()
            if heap_addr:
                return heap_addr
            else:
                err(f"Cannot find heap address for arena {self.ar_ptr:#x}")
                return 0
        return self.address + self.sizeof

    @property
    def heap_end(self) -> int:
        return self.address + self.size


class GlibcArena:
    """Glibc arena class"""

    NFASTBINS = 10
    NBINS = 128
    NSMALLBINS = 64
    BINMAPSHIFT = 5
    BITSPERMAP = 1 << BINMAPSHIFT
    BINMAPSIZE = NBINS // BITSPERMAP

    @staticmethod
    def malloc_state_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        fields = [
            ("mutex", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
        ]
        if gef and gef.libc.version and gef.libc.version >= (2, 27):
            # https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L1684
            fields += [
                ("have_fastchunks", ctypes.c_uint32),
                ("UNUSED_c", ctypes.c_uint32), # padding to align to 0x10
            ]
        fields += [
            ("fastbinsY", GlibcArena.NFASTBINS * pointer),
            ("top", pointer),
            ("last_remainder", pointer),
            ("bins", (GlibcArena.NBINS * 2 - 2) * pointer),
            ("binmap", GlibcArena.BINMAPSIZE * ctypes.c_uint32),
            ("next", pointer),
            ("next_free", pointer)
        ]
        if gef and gef.libc.version and gef.libc.version >= (2, 23):
            # https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1719
            fields += [
                ("attached_threads", pointer)
            ]
        fields += [
            ("system_mem", pointer),
            ("max_system_mem", pointer),
        ]
        class malloc_state_cls(ctypes.Structure):
            _fields_ = fields
        return malloc_state_cls

    def __init__(self, addr: str) -> None:
        try:
            self.__address : int = parse_address(f"&{addr}")
        except gdb.error:
            self.__address : int = GefHeapManager.find_main_arena_addr()
            # if `find_main_arena_addr` throws `gdb.error` on symbol lookup:
            # it means the session is not started, so just propagate the exception
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(GlibcArena.malloc_state_t())
        self._data = gef.memory.read(self.__address, ctypes.sizeof(GlibcArena.malloc_state_t()))
        self.__arena = GlibcArena.malloc_state_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    def __iter__(self) -> Generator["GlibcArena", None, None]:
        main_arena = int(gef.heap.main_arena)

        current_arena = self
        yield current_arena

        while True:
            if current_arena.next == 0 or current_arena.next == main_arena:
                break

            current_arena = GlibcArena(f"*{current_arena.next:#x} ")
            yield current_arena
        return

    def __eq__(self, other: "GlibcArena") -> bool:
        return self.__address == int(other)

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, top={self.top:#x}, " \
                f"last_remainder={self.last_remainder:#x}, next={self.next:#x}"
        return (f"{Color.colorify('Arena', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"GlibcArena(address={self.__address:#x}, size={self._sizeof})"

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def top(self) -> int:
        return self.__arena.top

    @property
    def last_remainder(self) -> int:
        return self.__arena.last_remainder

    @property
    def fastbinsY(self) -> ctypes.Array:
        return self.__arena.fastbinsY

    @property
    def bins(self) -> ctypes.Array:
        return self.__arena.bins

    @property
    def binmap(self) -> ctypes.Array:
        return self.__arena.binmap

    @property
    def next(self) -> int:
        return self.__arena.next

    @property
    def next_free(self) -> int:
        return self.__arena.next_free

    @property
    def attached_threads(self) -> int:
        return self.__arena.attached_threads

    @property
    def system_mem(self) -> int:
        return self.__arena.system_mem

    @property
    def max_system_mem(self) -> int:
        return self.__arena.max_system_mem

    def fastbin(self, i: int) -> Optional["GlibcFastChunk"]:
        """Return head chunk in fastbinsY[i]."""
        addr = int(self.fastbinsY[i])
        if addr == 0:
            return None
        return GlibcFastChunk(addr + 2 * gef.arch.ptrsize)

    def bin(self, i: int) -> Tuple[int, int]:
        idx = i * 2
        fd = int(self.bins[idx])
        bk = int(self.bins[idx + 1])
        return fd, bk

    def bin_at(self, i) -> int:
        header_sz = 2 * gef.arch.ptrsize
        offset = ctypes.addressof(self.__arena.bins) - ctypes.addressof(self.__arena)
        return self.__address + offset + (i-1) * 2 * gef.arch.ptrsize + header_sz

    def is_main_arena(self) -> bool:
        return gef.heap.main_arena is not None and int(self) == int(gef.heap.main_arena)

    def heap_addr(self, allow_unaligned: bool = False) -> Optional[int]:
        if self.is_main_arena():
            heap_section = gef.heap.base_address
            if not heap_section:
                return None
            return heap_section
        _addr = int(self) + self.sizeof
        if allow_unaligned:
            return _addr
        return gef.heap.malloc_align_address(_addr)

    def get_heap_info_list(self) -> Optional[List[GlibcHeapInfo]]:
        if self.is_main_arena():
            return None
        heap_addr = self.get_heap_for_ptr(self.top)
        heap_infos = [GlibcHeapInfo(heap_addr)]
        while heap_infos[-1].prev is not None:
            prev = int(heap_infos[-1].prev)
            heap_info = GlibcHeapInfo(prev)
            heap_infos.append(heap_info)
        return heap_infos[::-1]

    @staticmethod
    def get_heap_for_ptr(ptr: int) -> int:
        """Find the corresponding heap for a given pointer (int).
        See https://github.com/bminor/glibc/blob/glibc-2.34/malloc/arena.c#L129"""
        if is_32bit():
            default_mmap_threshold_max = 512 * 1024
        else:  # 64bit
            default_mmap_threshold_max = 4 * 1024 * 1024 * cached_lookup_type("long").sizeof
        heap_max_size = 2 * default_mmap_threshold_max
        return ptr & ~(heap_max_size - 1)

    @staticmethod
    def verify(addr: int) -> bool:
        """Verify that the address matches a possible valid GlibcArena"""
        try:
            test_arena = GlibcArena(f"*{addr:#x}")
            cur_arena = GlibcArena(f"*{test_arena.next:#x}")
            while cur_arena != test_arena:
                if cur_arena == 0:
                    return False
                cur_arena = GlibcArena(f"*{cur_arena.next:#x}")
        except Exception as e:
            return False
        return True


class GlibcChunk:
    """Glibc chunk class. The default behavior (from_base=False) is to interpret the data starting at the memory
    address pointed to as the chunk data. Setting from_base to True instead treats that data as the chunk header.
    Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/."""

    class ChunkFlags(enum.IntFlag):
        PREV_INUSE = 1
        IS_MMAPPED = 2
        NON_MAIN_ARENA = 4

        def __str__(self) -> str:
            return f" | ".join([
                Color.greenify("PREV_INUSE") if self.value & self.PREV_INUSE else Color.redify("PREV_INUSE"),
                Color.greenify("IS_MMAPPED") if self.value & self.IS_MMAPPED else Color.redify("IS_MMAPPED"),
                Color.greenify("NON_MAIN_ARENA") if self.value & self.NON_MAIN_ARENA else Color.redify("NON_MAIN_ARENA")
            ])

    @staticmethod
    def malloc_chunk_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if gef and gef.arch.ptrsize == 8 else ctypes.c_uint32
        class malloc_chunk_cls(ctypes.Structure):
            pass

        malloc_chunk_cls._fields_ = [
            ("prev_size", pointer),
            ("size", pointer),
            ("fd", pointer),
            ("bk", pointer),
            ("fd_nextsize", ctypes.POINTER(malloc_chunk_cls)),
            ("bk_nextsize", ctypes.POINTER(malloc_chunk_cls)),
        ]
        return malloc_chunk_cls

    def __init__(self, addr: int, from_base: bool = False, allow_unaligned: bool = True) -> None:
        ptrsize = gef.arch.ptrsize
        self.data_address = addr + 2 * ptrsize if from_base else addr
        self.base_address = addr if from_base else addr - 2 * ptrsize
        if not allow_unaligned:
            self.data_address = gef.heap.malloc_align_address(self.data_address)
        self.size_addr = int(self.data_address - ptrsize)
        self.prev_size_addr = self.base_address
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(GlibcChunk.malloc_chunk_t())
        self._data = gef.memory.read(
            self.base_address, ctypes.sizeof(GlibcChunk.malloc_chunk_t()))
        self._chunk = GlibcChunk.malloc_chunk_t().from_buffer_copy(self._data)
        return

    @property
    def prev_size(self) -> int:
        return self._chunk.prev_size

    @property
    def size(self) -> int:
        return self._chunk.size & (~0x07)

    @property
    def flags(self) -> ChunkFlags:
        return GlibcChunk.ChunkFlags(self._chunk.size & 0x07)

    @property
    def fd(self) -> int:
        return self._chunk.fd

    @property
    def bk(self) -> int:
        return self._chunk.bk

    @property
    def fd_nextsize(self) -> int:
        return self._chunk.fd_nextsize

    @property
    def bk_nextsize(self) -> int:
        return self._chunk.bk_nextsize

    def get_usable_size(self) -> int:
        # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4537
        ptrsz = gef.arch.ptrsize
        cursz = self.size
        if cursz == 0: return cursz
        if self.has_m_bit(): return cursz - 2 * ptrsz
        return cursz - ptrsz

    @property
    def usable_size(self) -> int:
        return self.get_usable_size()

    def get_prev_chunk_size(self) -> int:
        return gef.memory.read_integer(self.prev_size_addr)

    def __iter__(self) -> Generator["GlibcChunk", None, None]:
        current_chunk = self
        top = gef.heap.main_arena.top

        while True:
            yield current_chunk

            if current_chunk.base_address == top:
                break

            if current_chunk.size == 0:
                break

            next_chunk_addr = current_chunk.get_next_chunk_addr()

            if not Address(value=next_chunk_addr).valid:
                break

            next_chunk = current_chunk.get_next_chunk()
            if next_chunk is None:
                break

            current_chunk = next_chunk
        return

    def get_next_chunk(self, allow_unaligned: bool = False) -> "GlibcChunk":
        addr = self.get_next_chunk_addr()
        return GlibcChunk(addr, allow_unaligned=allow_unaligned)

    def get_next_chunk_addr(self) -> int:
        return self.data_address + self.size

    def has_p_bit(self) -> bool:
        return bool(self.flags & GlibcChunk.ChunkFlags.PREV_INUSE)

    def has_m_bit(self) -> bool:
        return bool(self.flags & GlibcChunk.ChunkFlags.IS_MMAPPED)

    def has_n_bit(self) -> bool:
        return bool(self.flags & GlibcChunk.ChunkFlags.NON_MAIN_ARENA)

    def is_used(self) -> bool:
        """Check if the current block is used by:
        - checking the M bit is true
        - or checking that next chunk PREV_INUSE flag is true"""
        if self.has_m_bit():
            return True

        next_chunk = self.get_next_chunk()
        return True if next_chunk.has_p_bit() else False

    def __str_sizes(self) -> str:
        msg = []
        failed = False

        try:
            msg.append("Chunk size: {0:d} ({0:#x})".format(self.size))
            msg.append("Usable size: {0:d} ({0:#x})".format(self.usable_size))
            failed = True
        except gdb.MemoryError:
            msg.append(f"Chunk size: Cannot read at {self.size_addr:#x} (corrupted?)")

        try:
            msg.append("Previous chunk size: {0:d} ({0:#x})".format(self.get_prev_chunk_size()))
            failed = True
        except gdb.MemoryError:
            msg.append(f"Previous chunk size: Cannot read at {self.base_address:#x} (corrupted?)")

        if failed:
            msg.append(str(self.flags))

        return "\n".join(msg)

    def _str_pointers(self) -> str:
        fwd = self.data_address
        bkw = self.data_address + gef.arch.ptrsize

        msg = []
        try:
            msg.append(f"Forward pointer: {self.fd:#x}")
        except gdb.MemoryError:
            msg.append(f"Forward pointer: {fwd:#x} (corrupted?)")

        try:
            msg.append(f"Backward pointer: {self.bk:#x}")
        except gdb.MemoryError:
            msg.append(f"Backward pointer: {bkw:#x} (corrupted?)")

        return "\n".join(msg)

    def __str__(self) -> str:
        return (f"{Color.colorify('Chunk', 'yellow bold underline')}(addr={self.data_address:#x}, "
                f"size={self.size:#x}, flags={self.flags!s})")

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_sizes(),
        ]
        if not self.is_used():
            msg.append(f"\n\n{self._str_pointers()}")
        return "\n".join(msg) + "\n"


class GlibcFastChunk(GlibcChunk):

    @property
    def fd(self) -> int:
        assert(gef and gef.libc.version)
        if gef.libc.version < (2, 32):
            return self._chunk.fd
        return self.reveal_ptr(self.data_address)

    def protect_ptr(self, pos: int, pointer: int) -> int:
        """https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L339"""
        assert(gef and gef.libc.version)
        if gef.libc.version < (2, 32):
            return pointer
        return (pos >> 12) ^ pointer

    def reveal_ptr(self, pointer: int) -> int:
        """https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L341"""
        assert(gef and gef.libc.version)
        if gef.libc.version < (2, 32):
            return pointer
        return gef.memory.read_integer(pointer) ^ (pointer >> 12)

class GlibcTcacheChunk(GlibcFastChunk):

    pass

@deprecated("Use GefLibcManager.find_libc_version()")
def get_libc_version() -> Tuple[int, ...]:
    return GefLibcManager.find_libc_version()

def titlify(text: str, color: Optional[str] = None, msg_color: Optional[str] = None) -> str:
    """Print a centered title."""
    _, cols = get_terminal_size()
    nb = (cols - len(text) - 2) // 2
    line_color = color or gef.config["theme.default_title_line"]
    text_color = msg_color or gef.config["theme.default_title_message"]

    msg = [Color.colorify(f"{HORIZONTAL_LINE * nb} ", line_color),
           Color.colorify(text, text_color),
           Color.colorify(f" {HORIZONTAL_LINE * nb}", line_color)]
    return "".join(msg)


def dbg(msg: str) -> None:
    if gef.config["gef.debug"] is True:
        gef_print(f"{Color.colorify('[=]', 'bold cyan')} {msg}")
    return


def err(msg: str) -> None:
    gef_print(f"{Color.colorify('[!]', 'bold red')} {msg}")
    return


def warn(msg: str) -> None:
    gef_print(f"{Color.colorify('[*]', 'bold yellow')} {msg}")
    return


def ok(msg: str) -> None:
    gef_print(f"{Color.colorify('[+]', 'bold green')} {msg}")
    return


def info(msg: str) -> None:
    gef_print(f"{Color.colorify('[+]', 'bold blue')} {msg}")
    return


def push_context_message(level: str, message: str) -> None:
    """Push the message to be displayed the next time the context is invoked."""
    if level not in ("error", "warn", "ok", "info"):
        err(f"Invalid level '{level}', discarding message")
        return
    gef.ui.context_messages.append((level, message))
    return


def show_last_exception() -> None:
    """Display the last Python exception."""

    def _show_code_line(fname: str, idx: int) -> str:
        fname = os.path.expanduser(os.path.expandvars(fname))
        with open(fname, "r") as f:
            _data = f.readlines()
        return _data[idx - 1] if 0 < idx < len(_data) else ""

    gef_print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()

    gef_print(" Exception raised ".center(80, HORIZONTAL_LINE))
    gef_print(f"{Color.colorify(exc_type.__name__, 'bold underline red')}: {exc_value}")
    gef_print(" Detailed stacktrace ".center(80, HORIZONTAL_LINE))

    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        filename, lineno, method, code = fs

        if not code or not code.strip():
            code = _show_code_line(filename, lineno)

        gef_print(f"""{DOWN_ARROW} File "{Color.yellowify(filename)}", line {lineno:d}, in {Color.greenify(method)}()""")
        gef_print(f"   {RIGHT_ARROW}    {code}")

    gef_print(" Version ".center(80, HORIZONTAL_LINE))
    gdb.execute("version full")
    gef_print(" Last 10 GDB commands ".center(80, HORIZONTAL_LINE))
    gdb.execute("show commands")
    gef_print(" Runtime environment ".center(80, HORIZONTAL_LINE))
    gef_print(f"* GDB: {gdb.VERSION}")
    gef_print(f"* Python: {sys.version_info.major:d}.{sys.version_info.minor:d}.{sys.version_info.micro:d} - {sys.version_info.releaselevel}")
    gef_print(f"* OS: {platform.system()} - {platform.release()} ({platform.machine()})")

    try:
        lsb_release = which("lsb_release")
        gdb.execute(f"!'{lsb_release}' -a")
    except FileNotFoundError:
        gef_print("lsb_release is missing, cannot collect additional debug information")

    gef_print(HORIZONTAL_LINE*80)
    gef_print("")
    return


def gef_pystring(x: bytes) -> str:
    """Returns a sanitized version as string of the bytes list given in input."""
    res = str(x, encoding="utf-8")
    substs = [("\n", "\\n"), ("\r", "\\r"), ("\t", "\\t"), ("\v", "\\v"), ("\b", "\\b"), ]
    for x, y in substs: res = res.replace(x, y)
    return res


def gef_pybytes(x: str) -> bytes:
    """Returns an immutable bytes list from the string given as input."""
    return bytes(str(x), encoding="utf-8")


@lru_cache()
def which(program: str) -> pathlib.Path:
    """Locate a command on the filesystem."""
    for path in os.environ["PATH"].split(os.pathsep):
        dirname = pathlib.Path(path)
        fpath = dirname / program
        if os.access(fpath, os.X_OK):
            return fpath

    raise FileNotFoundError(f"Missing file `{program}`")


def style_byte(b: int, color: bool = True) -> str:
    style = {
        "nonprintable": "yellow",
        "printable": "white",
        "00": "gray",
        "0a": "blue",
        "ff": "green",
    }
    sbyte = f"{b:02x}"
    if not color or gef.config["highlight.regex"]:
        return sbyte

    if sbyte in style:
        st = style[sbyte]
    elif chr(b) in (string.ascii_letters + string.digits + string.punctuation + " "):
        st = style.get("printable")
    else:
        st = style.get("nonprintable")
    if st:
        sbyte = Color.colorify(sbyte, st)
    return sbyte


def hexdump(source: ByteString, length: int = 0x10, separator: str = ".", show_raw: bool = False, show_symbol: bool = True, base: int = 0x00) -> str:
    """Return the hexdump of `src` argument.
    @param source *MUST* be of type bytes or bytearray
    @param length is the length of items per line
    @param separator is the default character to use if one byte is not printable
    @param show_raw if True, do not add the line nor the text translation
    @param base is the start address of the block being hexdump
    @return a string with the hexdump"""
    result = []
    align = gef.arch.ptrsize * 2 + 2 if is_alive() else 18

    for i in range(0, len(source), length):
        chunk = bytearray(source[i : i + length])
        hexa = " ".join([style_byte(b, color=not show_raw) for b in chunk])

        if show_raw:
            result.append(hexa)
            continue

        text = "".join([chr(b) if 0x20 <= b < 0x7F else separator for b in chunk])
        if show_symbol:
            sym = gdb_get_location_from_symbol(base + i)
            sym = "<{:s}+{:04x}>".format(*sym) if sym else ""
        else:
            sym = ""

        result.append(f"{base + i:#0{align}x} {sym}    {hexa:<{3 * length}}    {text}")
    return "\n".join(result)


def is_debug() -> bool:
    """Check if debug mode is enabled."""
    return gef.config["gef.debug"] is True


def buffer_output() -> bool:
    """Check if output should be buffered until command completion."""
    return gef.config["gef.buffer"] is True


def hide_context() -> bool:
    """Helper function to hide the context pane."""
    gef.ui.context_hidden = True
    return True


def unhide_context() -> bool:
    """Helper function to unhide the context pane."""
    gef.ui.context_hidden = False
    return True


class DisableContextOutputContext:
    def __enter__(self) -> None:
        hide_context()
        return

    def __exit__(self, *exc: Any) -> None:
        unhide_context()
        return


class RedirectOutputContext:
    def __init__(self, to_file: str = "/dev/null") -> None:
        if " " in to_file: raise ValueEror("Target filepath cannot contain spaces")
        self.redirection_target_file = to_file
        return

    def __enter__(self) -> None:
        """Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`."""
        gdb.execute("set logging overwrite")
        gdb.execute(f"set logging file {self.redirection_target_file}")
        gdb.execute("set logging redirect on")
        gdb.execute("set logging on")
        return

    def __exit__(self, *exc: Any) -> None:
        """Disable the output redirection, if any."""
        gdb.execute("set logging off")
        gdb.execute("set logging redirect off")
        return


def enable_redirect_output(to_file: str = "/dev/null") -> None:
    """Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`."""
    if " " in to_file: raise ValueEror("Target filepath cannot contain spaces")
    gdb.execute("set logging overwrite")
    gdb.execute(f"set logging file {to_file}")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")
    return


def disable_redirect_output() -> None:
    """Disable the output redirection, if any."""
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")
    return


def gef_makedirs(path: str, mode: int = 0o755) -> pathlib.Path:
    """Recursive mkdir() creation. If successful, return the absolute path of the directory created."""
    fpath = pathlib.Path(path)
    if not fpath.is_dir():
        fpath.mkdir(mode=mode, exist_ok=True, parents=True)
    return fpath.absolute()


@lru_cache()
def gdb_lookup_symbol(sym: str) -> Optional[Tuple[Optional[str], Optional[Tuple[gdb.Symtab_and_line, ...]]]]:
    """Fetch the proper symbol or None if not defined."""
    try:
        return gdb.decode_line(sym)[1]
    except gdb.error:
        return None


@lru_cache(maxsize=512)
def gdb_get_location_from_symbol(address: int) -> Optional[Tuple[str, int]]:
    """Retrieve the location of the `address` argument from the symbol table.
    Return a tuple with the name and offset if found, None otherwise."""
    # this is horrible, ugly hack and shitty perf...
    # find a *clean* way to get gdb.Location from an address
    sym = str(gdb.execute(f"info symbol {address:#x}", to_string=True))
    if sym.startswith("No symbol matches"):
        return None

    i = sym.find(" in section ")
    sym = sym[:i].split()
    name, offset = sym[0], 0
    if len(sym) == 3 and sym[2].isdigit():
        offset = int(sym[2])
    return name, offset


def gdb_disassemble(start_pc: int, **kwargs: int) -> Generator[Instruction, None, None]:
    """Disassemble instructions from `start_pc` (Integer). Accepts the following named
    parameters:
    - `end_pc` (Integer) only instructions whose start address fall in the interval from
      start_pc to end_pc are returned.
    - `count` (Integer) list at most this many disassembled instructions
    If `end_pc` and `count` are not provided, the function will behave as if `count=1`.
    Return an iterator of Instruction objects
    """
    frame = gdb.selected_frame()
    arch = frame.architecture()

    for insn in arch.disassemble(start_pc, **kwargs):
        assert isinstance(insn["addr"], int)
        assert isinstance(insn["length"], int)
        assert isinstance(insn["asm"], str)
        address = insn["addr"]
        asm = insn["asm"].rstrip().split(None, 1)
        if len(asm) > 1:
            mnemo, operands = asm
            operands = operands.split(",")
        else:
            mnemo, operands = asm[0], []

        loc = gdb_get_location_from_symbol(address)
        location = "<{}+{}>".format(*loc) if loc else ""

        opcodes = gef.memory.read(insn["addr"], insn["length"])

        yield Instruction(address, location, mnemo, operands, opcodes)


def gdb_get_nth_previous_instruction_address(addr: int, n: int) -> Optional[int]:
    """Return the address (Integer) of the `n`-th instruction before `addr`."""
    # fixed-length ABI
    if gef.arch.instruction_length:
        return max(0, addr - n * gef.arch.instruction_length)

    # variable-length ABI
    cur_insn_addr = gef_current_instruction(addr).address

    # we try to find a good set of previous instructions by "guessing" disassembling backwards
    # the 15 comes from the longest instruction valid size
    for i in range(15 * n, 0, -1):
        try:
            insns = list(gdb_disassemble(addr - i, end_pc=cur_insn_addr))
        except gdb.MemoryError:
            # this is because we can hit an unmapped page trying to read backward
            break

        # 1. check that the disassembled instructions list size can satisfy
        if len(insns) < n + 1:  # we expect the current instruction plus the n before it
            continue

        # If the list of instructions is longer than what we need, then we
        # could get lucky and already have more than what we need, so slice down
        insns = insns[-n - 1 :]

        # 2. check that the sequence ends with the current address
        if insns[-1].address != cur_insn_addr:
            continue

        # 3. check all instructions are valid
        if all(insn.is_valid() for insn in insns):
            return insns[0].address

    return None


@deprecated(solution="Use `gef_instruction_n().address`")
def gdb_get_nth_next_instruction_address(addr: int, n: int) -> int:
    """Return the address of the `n`-th instruction after `addr`. """
    return gef_instruction_n(addr, n).address


def gef_instruction_n(addr: int, n: int) -> Instruction:
    """Return the `n`-th instruction after `addr` as an Instruction object. Note that `n` is treated as
    an positive index, starting from 0 (current instruction address)"""
    return list(gdb_disassemble(addr, count=n + 1))[n]


def gef_get_instruction_at(addr: int) -> Instruction:
    """Return the full Instruction found at the specified address."""
    insn = next(gef_disassemble(addr, 1))
    return insn


def gef_current_instruction(addr: int) -> Instruction:
    """Return the current instruction as an Instruction object."""
    return gef_instruction_n(addr, 0)


def gef_next_instruction(addr: int) -> Instruction:
    """Return the next instruction as an Instruction object."""
    return gef_instruction_n(addr, 1)


def gef_disassemble(addr: int, nb_insn: int, nb_prev: int = 0) -> Generator[Instruction, None, None]:
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`.
    Return an iterator of Instruction objects."""
    nb_insn = max(1, nb_insn)

    if nb_prev:
        try:
            start_addr = gdb_get_nth_previous_instruction_address(addr, nb_prev)
            if start_addr:
                    for insn in gdb_disassemble(start_addr, count=nb_prev):
                        if insn.address == addr: break
                        yield insn
        except gdb.MemoryError:
            # If the address pointing to the previous instruction(s) is not mapped, simply skip them
            pass

    for insn in gdb_disassemble(addr, count=nb_insn):
        yield insn


def gef_execute_external(command: Sequence[str], as_list: bool = False, **kwargs: Any) -> Union[str, List[str]]:
    """Execute an external command and return the result."""
    res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=kwargs.get("shell", False))
    return [gef_pystring(_) for _ in res.splitlines()] if as_list else gef_pystring(res)


def gef_execute_gdb_script(commands: str) -> None:
    """Execute the parameter `source` as GDB command. This is done by writing `commands` to
    a temporary file, which is then executed via GDB `source` command. The tempfile is then deleted."""
    fd, fname = tempfile.mkstemp(suffix=".gdb", prefix="gef_")
    with os.fdopen(fd, "w") as f:
        f.write(commands)
        f.flush()

    fname = pathlib.Path(fname)
    if fname.is_file() and os.access(fname, os.R_OK):
        gdb.execute(f"source {fname}")
        fname.unlink()
    return


@deprecated("Use Elf(fname).checksec()")
def checksec(filename: str) -> Dict[str, bool]:
    return Elf(filename).checksec


@lru_cache()
def get_arch() -> str:
    """Return the binary's architecture."""
    if is_alive():
        arch = gdb.selected_frame().architecture()
        return arch.name()

    arch_str = gdb.execute("show architecture", to_string=True).strip()
    pat = "The target architecture is set automatically (currently "
    if arch_str.startswith(pat):
        arch_str = arch_str[len(pat):].rstrip(")")
        return arch_str

    pat = "The target architecture is assumed to be "
    if arch_str.startswith(pat):
        return arch_str[len(pat):]

    pat = "The target architecture is set to "
    if arch_str.startswith(pat):
        # GDB version >= 10.1
        if '"auto"' in arch_str:
            return re.findall(r"currently \"(.+)\"", arch_str)[0]
        return re.findall(r"\"(.+)\"", arch_str)[0]

    # Unknown, we throw an exception to be safe
    raise RuntimeError(f"Unknown architecture: {arch_str}")


@deprecated("Use `gef.binary.entry_point` instead")
def get_entry_point() -> Optional[int]:
    """Return the binary entry point."""
    return gef.binary.entry_point if gef.binary else None


def is_pie(fpath: str) -> bool:
    return Elf(fpath).checksec["PIE"]


@deprecated("Prefer `gef.arch.endianness == Endianness.BIG_ENDIAN`")
def is_big_endian() -> bool:
    return gef.arch.endianness == Endianness.BIG_ENDIAN


@deprecated("gef.arch.endianness == Endianness.LITTLE_ENDIAN")
def is_little_endian() -> bool:
    return gef.arch.endianness == Endianness.LITTLE_ENDIAN


def flags_to_human(reg_value: int, value_table: Dict[int, str]) -> str:
    """Return a human readable string showing the flag states."""
    flags = []
    for bit_index, name in value_table.items():
        flags.append(Color.boldify(name.upper()) if reg_value & (1<<bit_index) != 0 else name.lower())
    return f"[{' '.join(flags)}]"


@lru_cache()
def get_section_base_address(name: str) -> Optional[int]:
    section = process_lookup_path(name)
    return section.page_start if section else None


@lru_cache()
def get_zone_base_address(name: str) -> Optional[int]:
    zone = file_lookup_name_path(name, get_filepath())
    return zone.zone_start if zone else None


#
# Architecture classes
#
@deprecated("Using the decorator `register_architecture` is unecessary")
def register_architecture(cls: Type["Architecture"]) -> Type["Architecture"]:
    return cls

class ArchitectureBase:
    """Class decorator for declaring an architecture to GEF."""
    aliases: Union[Tuple[()], Tuple[Union[str, Elf.Abi], ...]] = ()

    def __init_subclass__(cls: Type["ArchitectureBase"], **kwargs):
        global __registered_architectures__
        super().__init_subclass__(**kwargs)
        for key in getattr(cls, "aliases"):
            if issubclass(cls, Architecture):
                __registered_architectures__[key] = cls
        return


class Architecture(ArchitectureBase):
    """Generic metaclass for the architecture supported by GEF."""

    # Mandatory defined attributes by inheriting classes
    arch: str
    mode: str
    all_registers: Union[Tuple[()], Tuple[str, ...]]
    nop_insn: bytes
    return_register: str
    flag_register: Optional[str]
    instruction_length: Optional[int]
    flags_table: Dict[int, str]
    syscall_register: Optional[str]
    syscall_instructions: Union[Tuple[()], Tuple[str, ...]]
    function_parameters: Union[Tuple[()], Tuple[str, ...]]

    # Optionally defined attributes
    _ptrsize: Optional[int] = None
    _endianness: Optional[Endianness] = None
    special_registers: Union[Tuple[()], Tuple[str, ...]] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        attributes = ("arch", "mode", "aliases", "all_registers", "nop_insn",
             "return_register", "flag_register", "instruction_length", "flags_table",
             "function_parameters",)
        if not all(map(lambda x: hasattr(cls, x), attributes)):
            raise NotImplementedError

    def __str__(self) -> str:
        return f"Architecture({self.arch}, {self.mode or 'None'}, {repr(self.endianness)})"

    @staticmethod
    def supports_gdb_arch(gdb_arch: str) -> Optional[bool]:
        """If implemented by a child `Architecture`, this function dictates if the current class
        supports the loaded ELF file (which can be accessed via `gef.binary`). This callback
        function will override any assumption made by GEF to determine the architecture."""
        return None

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        raise NotImplementedError

    def is_call(self, insn: Instruction) -> bool:
        raise NotImplementedError

    def is_ret(self, insn: Instruction) -> bool:
        raise NotImplementedError

    def is_conditional_branch(self, insn: Instruction) -> bool:
        raise NotImplementedError

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        raise NotImplementedError

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        raise NotImplementedError

    def canary_address(self) -> int:
        raise NotImplementedError

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        raise NotImplementedError

    def reset_caches(self) -> None:
        self.__get_register_for_selected_frame.cache_clear()
        return

    def __get_register(self, regname: str) -> int:
        """Return a register's value."""
        curframe = gdb.selected_frame()
        key = curframe.pc() ^ int(curframe.read_register('sp')) # todo: check when/if gdb.Frame implements `level()`
        return self.__get_register_for_selected_frame(regname, key)

    @lru_cache()
    def __get_register_for_selected_frame(self, regname: str, hash_key: int) -> int:
        # 1st chance
        try:
            return parse_address(regname)
        except gdb.error:
            pass

        # 2nd chance - if an exception, propagate it
        regname = regname.lstrip("$")
        value = gdb.selected_frame().read_register(regname)
        return int(value)

    def register(self, name: str) -> int:
        if not is_alive():
            raise gdb.error("No debugging session active")
        return self.__get_register(name)

    @property
    def registers(self) -> Generator[str, None, None]:
        yield from self.all_registers

    @property
    def pc(self) -> int:
        return self.register("$pc")

    @property
    def sp(self) -> int:
        return self.register("$sp")

    @property
    def fp(self) -> int:
        return self.register("$fp")

    @property
    def ptrsize(self) -> int:
        if not self._ptrsize:
            res = cached_lookup_type("size_t")
            if res is not None:
                self._ptrsize = res.sizeof
            else:
                self._ptrsize = gdb.parse_and_eval("$pc").type.sizeof
        return self._ptrsize

    @property
    def endianness(self) -> Endianness:
        if not self._endianness:
            output = gdb.execute("show endian", to_string=True).strip().lower()
            if "little endian" in output:
                self._endianness = Endianness.LITTLE_ENDIAN
            elif "big endian" in output:
                self._endianness = Endianness.BIG_ENDIAN
            else:
                raise OSError(f"No valid endianess found in '{output}'")
        return self._endianness

    def get_ith_parameter(self, i: int, in_func: bool = True) -> Tuple[str, Optional[int]]:
        """Retrieves the correct parameter used for the current function call."""
        reg = self.function_parameters[i]
        val = self.register(reg)
        key = reg
        return key, val


class GenericArchitecture(Architecture):
    arch = "Generic"
    mode = ""
    aliases = ("GenericArchitecture",)
    all_registers = ()
    instruction_length = 0
    return_register = ""
    function_parameters = ()
    syscall_register = ""
    syscall_instructions = ()
    nop_insn = b""
    flag_register = None
    flags_table = {}


class RISCV(Architecture):
    arch = "RISCV"
    mode = "RISCV"
    aliases = ("RISCV", Elf.Abi.RISCV)
    all_registers = ("$zero", "$ra", "$sp", "$gp", "$tp", "$t0", "$t1",
                     "$t2", "$fp", "$s1", "$a0", "$a1", "$a2", "$a3",
                     "$a4", "$a5", "$a6", "$a7", "$s2", "$s3", "$s4",
                     "$s5", "$s6", "$s7", "$s8", "$s9", "$s10", "$s11",
                     "$t3", "$t4", "$t5", "$t6",)
    return_register = "$a0"
    function_parameters = ("$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7")
    syscall_register = "$a7"
    syscall_instructions = ("ecall",)
    nop_insn = b"\x00\x00\x00\x13"
    # RISC-V has no flags registers
    flag_register = None
    flags_table = {}

    @property
    def instruction_length(self) -> int:
        return 4

    def is_call(self, insn: Instruction) -> bool:
        return insn.mnemonic == "call"

    def is_ret(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        if mnemo == "ret":
            return True
        elif (mnemo == "jalr" and insn.operands[0] == "zero" and
              insn.operands[1] == "ra" and insn.operands[2] == 0):
            return True
        elif (mnemo == "c.jalr" and insn.operands[0] == "ra"):
            return True
        return False

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        raise OSError(f"Architecture {cls.arch} not supported yet")

    @property
    def ptrsize(self) -> int:
        if self._ptrsize is not None:
            return self._ptrsize
        if is_alive():
            self._ptrsize = gdb.parse_and_eval("$pc").type.sizeof
            return self._ptrsize
        return 4

    def is_conditional_branch(self, insn: Instruction) -> bool:
        return insn.mnemonic.startswith("b")

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        def long_to_twos_complement(v: int) -> int:
            """Convert a python long value to its two's complement."""
            if is_32bit():
                if v & 0x80000000:
                    return v - 0x100000000
            elif is_64bit():
                if v & 0x8000000000000000:
                    return v - 0x10000000000000000
            else:
                raise OSError("RISC-V: ELF file is not ELF32 or ELF64. This is not currently supported")
            return v

        mnemo = insn.mnemonic
        condition = mnemo[1:]

        if condition.endswith("z"):
            # r2 is the zero register if we are comparing to 0
            rs1 = gef.arch.register(insn.operands[0])
            rs2 = gef.arch.register("$zero")
            condition = condition[:-1]
        elif len(insn.operands) > 2:
            # r2 is populated with the second operand
            rs1 = gef.arch.register(insn.operands[0])
            rs2 = gef.arch.register(insn.operands[1])
        else:
            raise OSError(f"RISC-V: Failed to get rs1 and rs2 for instruction: `{insn}`")

        # If the conditional operation is not unsigned, convert the python long into
        # its two's complement
        if not condition.endswith("u"):
            rs2 = long_to_twos_complement(rs2)
            rs1 = long_to_twos_complement(rs1)
        else:
            condition = condition[:-1]

        if condition == "eq":
            if rs1 == rs2: taken, reason = True, f"{rs1}={rs2}"
            else: taken, reason = False, f"{rs1}!={rs2}"
        elif condition == "ne":
            if rs1 != rs2: taken, reason = True, f"{rs1}!={rs2}"
            else: taken, reason = False, f"{rs1}={rs2}"
        elif condition == "lt":
            if rs1 < rs2: taken, reason = True, f"{rs1}<{rs2}"
            else: taken, reason = False, f"{rs1}>={rs2}"
        elif condition == "le":
            if rs1 <= rs2: taken, reason = True, f"{rs1}<={rs2}"
            else: taken, reason = False, f"{rs1}>{rs2}"
        elif condition == "ge":
            if rs1 < rs2: taken, reason = True, f"{rs1}>={rs2}"
            else: taken, reason = False, f"{rs1}<{rs2}"
        else:
            raise OSError(f"RISC-V: Conditional instruction `{insn}` not supported yet")

        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        ra = None
        if self.is_ret(insn):
            ra = gef.arch.register("$ra")
        elif frame.older():
            ra = frame.older().pc()
        return ra


class ARM(Architecture):
    aliases = ("ARM", Elf.Abi.ARM)
    arch = "ARM"
    all_registers = ("$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6",
                     "$r7", "$r8", "$r9", "$r10", "$r11", "$r12", "$sp",
                     "$lr", "$pc", "$cpsr",)

    nop_insn = b"\x00\xf0\x20\xe3" # hint #0
    return_register = "$r0"
    flag_register: str = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast",
        5: "thumb",
    }
    function_parameters = ("$r0", "$r1", "$r2", "$r3")
    syscall_register = "$r7"
    syscall_instructions = ("swi 0x0", "swi NR")
    _endianness = Endianness.LITTLE_ENDIAN

    def is_thumb(self) -> bool:
        """Determine if the machine is currently in THUMB mode."""
        return is_alive() and (self.cpsr & (1 << 5) == 1)

    @property
    def pc(self) -> Optional[int]:
        pc = gef.arch.register("$pc")
        if self.is_thumb():
            pc += 1
        return pc

    @property
    def cpsr(self) -> int:
        if not is_alive():
            raise RuntimeError("Cannot get CPSR, program not started?")
        return gef.arch.register(self.flag_register)

    @property
    def mode(self) -> str:
        return "THUMB" if self.is_thumb() else "ARM"

    @property
    def instruction_length(self) -> Optional[int]:
        # Thumb instructions have variable-length (2 or 4-byte)
        return None if self.is_thumb() else 4

    @property
    def ptrsize(self) -> int:
        return 4

    def is_call(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blx"}
        return mnemo in call_mnemos

    def is_ret(self, insn: Instruction) -> bool:
        pop_mnemos = {"pop"}
        branch_mnemos = {"bl", "bx"}
        write_mnemos = {"ldr", "add"}
        if insn.mnemonic in pop_mnemos:
            return insn.operands[-1] == " pc}"
        if insn.mnemonic in branch_mnemos:
            return insn.operands[-1] == "lr"
        if insn.mnemonic in write_mnemos:
            return insn.operands[0] == "pc"
        return False

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        # https://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
        if val is None:
            reg = self.flag_register
            val = gef.arch.register(reg)
        return flags_to_human(val, self.flags_table)

    def is_conditional_branch(self, insn: Instruction) -> bool:
        conditions = {"eq", "ne", "lt", "le", "gt", "ge", "vs", "vc", "mi", "pl", "hi", "ls", "cc", "cs"}
        return insn.mnemonic[-2:] in conditions

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo = insn.mnemonic
        # ref: https://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = gef.arch.register(self.flag_register)
        taken, reason = False, ""

        if mnemo.endswith("eq"): taken, reason = bool(val&(1<<flags["zero"])), "Z"
        elif mnemo.endswith("ne"): taken, reason = not bool(val&(1<<flags["zero"])), "!Z"
        elif mnemo.endswith("lt"):
            taken, reason = bool(val&(1<<flags["negative"])) != bool(val&(1<<flags["overflow"])), "N!=V"
        elif mnemo.endswith("le"):
            taken, reason = bool(val&(1<<flags["zero"])) or \
                bool(val&(1<<flags["negative"])) != bool(val&(1<<flags["overflow"])), "Z || N!=V"
        elif mnemo.endswith("gt"):
            taken, reason = bool(val&(1<<flags["zero"])) == 0 and \
                bool(val&(1<<flags["negative"])) == bool(val&(1<<flags["overflow"])), "!Z && N==V"
        elif mnemo.endswith("ge"):
            taken, reason = bool(val&(1<<flags["negative"])) == bool(val&(1<<flags["overflow"])), "N==V"
        elif mnemo.endswith("vs"): taken, reason = bool(val&(1<<flags["overflow"])), "V"
        elif mnemo.endswith("vc"): taken, reason = not val&(1<<flags["overflow"]), "!V"
        elif mnemo.endswith("mi"):
            taken, reason = bool(val&(1<<flags["negative"])), "N"
        elif mnemo.endswith("pl"):
            taken, reason = not val&(1<<flags["negative"]), "N==0"
        elif mnemo.endswith("hi"):
            taken, reason = bool(val&(1<<flags["carry"])) and not bool(val&(1<<flags["zero"])), "C && !Z"
        elif mnemo.endswith("ls"):
            taken, reason = not val&(1<<flags["carry"]) or bool(val&(1<<flags["zero"])), "!C || Z"
        elif mnemo.endswith("cs"): taken, reason = bool(val&(1<<flags["carry"])), "C"
        elif mnemo.endswith("cc"): taken, reason = not val&(1<<flags["carry"]), "!C"
        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> int:
        ra = None
        if self.is_ret(insn):
            # If it's a pop, we have to peek into the stack, otherwise use lr
            if insn.mnemonic == "pop":
                ra_addr = gef.arch.sp + (len(insn.operands)-1) * self.ptrsize
                ra = to_unsigned_long(dereference(ra_addr))
            elif insn.mnemonic == "ldr":
                return to_unsigned_long(dereference(gef.arch.sp))
            else:  # 'bx lr' or 'add pc, lr, #0'
                return gef.arch.register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        _NR_mprotect = 125
        insns = [
            "push {r0-r2, r7}",
            f"mov r1, {addr & 0xffff:d}",
            f"mov r0, {(addr & 0xffff0000) >> 16:d}",
            "lsl r0, r0, 16",
            "add r0, r0, r1",
            f"mov r1, {size & 0xffff:d}",
            f"mov r2, {perm.value & 0xff:d}",
            f"mov r7, {_NR_mprotect:d}",
            "svc 0",
            "pop {r0-r2, r7}",
        ]
        return "; ".join(insns)


class AARCH64(ARM):
    aliases = ("ARM64", "AARCH64", Elf.Abi.AARCH64)
    arch = "ARM64"
    mode: str = ""

    all_registers = (
        "$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7",
        "$x8", "$x9", "$x10", "$x11", "$x12", "$x13", "$x14","$x15",
        "$x16", "$x17", "$x18", "$x19", "$x20", "$x21", "$x22", "$x23",
        "$x24", "$x25", "$x26", "$x27", "$x28", "$x29", "$x30", "$sp",
        "$pc", "$cpsr", "$fpsr", "$fpcr",)
    return_register = "$x0"
    flag_register = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        9: "endian",
        6: "fast",
        5: "t32",
        4: "m[4]",
    }
    nop_insn = b"\x1f\x20\x03\xd5" # hint #0
    function_parameters = ("$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7",)
    syscall_register = "$x8"
    syscall_instructions = ("svc $x0",)

    def is_call(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blr"}
        return mnemo in call_mnemos

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        # https://events.linuxfoundation.org/sites/events/files/slides/KoreaLinuxForum-2014.pdf
        reg = self.flag_register
        if not val:
            val = gef.arch.register(reg)
        return flags_to_human(val, self.flags_table)

    def is_aarch32(self) -> bool:
        """Determine if the CPU is currently in AARCH32 mode from runtime."""
        return (self.cpsr & (1 << 4) != 0) and (self.cpsr & (1 << 5) == 0)

    def is_thumb32(self) -> bool:
        """Determine if the CPU is currently in THUMB32 mode from runtime."""
        return (self.cpsr & (1 << 4) == 1) and (self.cpsr & (1 << 5) == 1)

    @property
    def ptrsize(self) -> int:
        """Determine the size of pointer from the current CPU mode"""
        if not is_alive():
            return 8
        if self.is_aarch32():
            return 4
        if self.is_thumb32():
            return 2
        return 8

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        _NR_mprotect = 226
        insns = [
            "str x8, [sp, -16]!",
            "str x0, [sp, -16]!",
            "str x1, [sp, -16]!",
            "str x2, [sp, -16]!",
            f"mov x8, {_NR_mprotect:d}",
            f"movz x0, {addr & 0xFFFF:#x}",
            f"movk x0, {(addr >> 16) & 0xFFFF:#x}, lsl 16",
            f"movk x0, {(addr >> 32) & 0xFFFF:#x}, lsl 32",
            f"movk x0, {(addr >> 48) & 0xFFFF:#x}, lsl 48",
            f"movz x1, {size & 0xFFFF:#x}",
            f"movk x1, {(size >> 16) & 0xFFFF:#x}, lsl 16",
            f"mov x2, {perm.value:d}",
            "svc 0",
            "ldr x2, [sp], 16",
            "ldr x1, [sp], 16",
            "ldr x0, [sp], 16",
            "ldr x8, [sp], 16",
        ]
        return "; ".join(insns)

    def is_conditional_branch(self, insn: Instruction) -> bool:
        # https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf
        # sect. 5.1.1
        mnemo = insn.mnemonic
        branch_mnemos = {"cbnz", "cbz", "tbnz", "tbz"}
        return mnemo.startswith("b.") or mnemo in branch_mnemos

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo, operands = insn.mnemonic, insn.operands
        taken, reason = False, ""

        if mnemo in {"cbnz", "cbz", "tbnz", "tbz"}:
            reg = f"${operands[0]}"
            op = gef.arch.register(reg)
            if mnemo == "cbnz":
                if op!=0: taken, reason = True, f"{reg}!=0"
                else: taken, reason = False, f"{reg}==0"
            elif mnemo == "cbz":
                if op == 0: taken, reason = True, f"{reg}==0"
                else: taken, reason = False, f"{reg}!=0"
            elif mnemo == "tbnz":
                # operands[1] has one or more white spaces in front, then a #, then the number
                # so we need to eliminate them
                i = int(operands[1].strip().lstrip("#"))
                if (op & 1<<i) != 0: taken, reason = True, f"{reg}&1<<{i}!=0"
                else: taken, reason = False, f"{reg}&1<<{i}==0"
            elif mnemo == "tbz":
                # operands[1] has one or more white spaces in front, then a #, then the number
                # so we need to eliminate them
                i = int(operands[1].strip().lstrip("#"))
                if (op & 1<<i) == 0: taken, reason = True, f"{reg}&1<<{i}==0"
                else: taken, reason = False, f"{reg}&1<<{i}!=0"

        if not reason:
            taken, reason = super().is_branch_taken(insn)
        return taken, reason


class X86(Architecture):
    aliases: Tuple[Union[str, Elf.Abi], ...] = ("X86", Elf.Abi.X86_32)
    arch = "X86"
    mode = "32"

    nop_insn = b"\x90"
    flag_register: str = "$eflags"
    special_registers = ("$cs", "$ss", "$ds", "$es", "$fs", "$gs", )
    gpr_registers = ("$eax", "$ebx", "$ecx", "$edx", "$esp", "$ebp", "$esi", "$edi", "$eip", )
    all_registers = gpr_registers + ( flag_register,) + special_registers
    instruction_length = None
    return_register = "$eax"
    function_parameters = ("$esp", )
    flags_table = {
        6: "zero",
        0: "carry",
        2: "parity",
        4: "adjust",
        7: "sign",
        8: "trap",
        9: "interrupt",
        10: "direction",
        11: "overflow",
        16: "resume",
        17: "virtualx86",
        21: "identification",
    }
    syscall_register = "$eax"
    syscall_instructions = ("sysenter", "int 0x80")
    _ptrsize = 4
    _endianness = Endianness.LITTLE_ENDIAN

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        reg = self.flag_register
        if not val:
            val = gef.arch.register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        call_mnemos = {"call", "callq"}
        return mnemo in call_mnemos

    def is_ret(self, insn: Instruction) -> bool:
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        branch_mnemos = {
            "ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
            "jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
            "jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
            "jo", "jp", "jpe", "js"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo = insn.mnemonic
        # all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = gef.arch.register(self.flag_register)

        taken, reason = False, ""

        if mnemo in ("ja", "jnbe"):
            taken, reason = not val&(1<<flags["carry"]) and not bool(val&(1<<flags["zero"])), "!C && !Z"
        elif mnemo in ("jae", "jnb", "jnc"):
            taken, reason = not val&(1<<flags["carry"]), "!C"
        elif mnemo in ("jb", "jc", "jnae"):
            taken, reason = bool(val&(1<<flags["carry"])) != 0, "C"
        elif mnemo in ("jbe", "jna"):
            taken, reason = bool(val&(1<<flags["carry"])) or bool(val&(1<<flags["zero"])), "C || Z"
        elif mnemo in ("jcxz", "jecxz", "jrcxz"):
            cx = gef.arch.register("$rcx") if is_x86_64() else gef.arch.register("$ecx")
            taken, reason = cx == 0, "!$CX"
        elif mnemo in ("je", "jz"):
            taken, reason = bool(val&(1<<flags["zero"])), "Z"
        elif mnemo in ("jne", "jnz"):
            taken, reason = not bool(val&(1<<flags["zero"])), "!Z"
        elif mnemo in ("jg", "jnle"):
            taken, reason = not bool(val&(1<<flags["zero"])) and bool(val&(1<<flags["overflow"])) == bool(val&(1<<flags["sign"])), "!Z && S==O"
        elif mnemo in ("jge", "jnl"):
            taken, reason = bool(val&(1<<flags["sign"])) == bool(val&(1<<flags["overflow"])), "S==O"
        elif mnemo in ("jl", "jnge"):
            taken, reason = bool(val&(1<<flags["overflow"]) != val&(1<<flags["sign"])), "S!=O"
        elif mnemo in ("jle", "jng"):
            taken, reason = bool(val&(1<<flags["zero"])) or bool(val&(1<<flags["overflow"])) != bool(val&(1<<flags["sign"])), "Z || S!=O"
        elif mnemo in ("jo",):
            taken, reason = bool(val&(1<<flags["overflow"])), "O"
        elif mnemo in ("jno",):
            taken, reason = not val&(1<<flags["overflow"]), "!O"
        elif mnemo in ("jpe", "jp"):
            taken, reason = bool(val&(1<<flags["parity"])), "P"
        elif mnemo in ("jnp", "jpo"):
            taken, reason = not val&(1<<flags["parity"]), "!P"
        elif mnemo in ("js",):
            taken, reason = bool(val&(1<<flags["sign"])) != 0, "S"
        elif mnemo in ("jns",):
            taken, reason = not val&(1<<flags["sign"]), "!S"
        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        ra = None
        if self.is_ret(insn):
            ra = to_unsigned_long(dereference(gef.arch.sp))
        if frame.older():
            ra = frame.older().pc()

        return ra

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        _NR_mprotect = 125
        insns = [
            "pushad",
            "pushfd",
            f"mov eax, {_NR_mprotect:d}",
            f"mov ebx, {addr:d}",
            f"mov ecx, {size:d}",
            f"mov edx, {perm.value:d}",
            "int 0x80",
            "popfd",
            "popad",
        ]
        return "; ".join(insns)

    def get_ith_parameter(self, i: int, in_func: bool = True) -> Tuple[str, Optional[int]]:
        if in_func:
            i += 1  # Account for RA being at the top of the stack
        sp = gef.arch.sp
        sz = gef.arch.ptrsize
        loc = sp + (i * sz)
        val = gef.memory.read_integer(loc)
        key = f"[sp + {i * sz:#x}]"
        return key, val


class X86_64(X86):
    aliases = ("X86_64", Elf.Abi.X86_64, "i386:x86-64")
    arch = "X86"
    mode = "64"

    gpr_registers = (
        "$rax", "$rbx", "$rcx", "$rdx", "$rsp", "$rbp", "$rsi", "$rdi", "$rip",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", )
    all_registers = gpr_registers + ( X86.flag_register, ) + X86.special_registers
    return_register = "$rax"
    function_parameters = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    syscall_register = "$rax"
    syscall_instructions = ["syscall"]
    # We don't want to inherit x86's stack based param getter
    get_ith_parameter = Architecture.get_ith_parameter
    _ptrsize = 8

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        _NR_mprotect = 10
        insns = [
            "pushfq",
            "push rax",
            "push rdi",
            "push rsi",
            "push rdx",
            "push rcx",
            "push r11",
            f"mov rax, {_NR_mprotect:d}",
            f"mov rdi, {addr:d}",
            f"mov rsi, {size:d}",
            f"mov rdx, {perm.value:d}",
            "syscall",
            "pop r11",
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "pop rax",
            "popfq",
        ]
        return "; ".join(insns)

    def canary_address(self) -> int:
        return self.register("fs_base") + 0x28

class PowerPC(Architecture):
    aliases = ("PowerPC", Elf.Abi.POWERPC, "PPC")
    arch = "PPC"
    mode = "PPC32"

    all_registers = (
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$pc", "$msr", "$cr", "$lr", "$ctr", "$xer", "$trap",)
    instruction_length = 4
    nop_insn = b"\x60\x00\x00\x00" # https://developer.ibm.com/articles/l-ppc/
    return_register = "$r0"
    flag_register: str = "$cr"
    flags_table = {
        3: "negative[0]",
        2: "positive[0]",
        1: "equal[0]",
        0: "overflow[0]",
        # cr7
        31: "less[7]",
        30: "greater[7]",
        29: "equal[7]",
        28: "overflow[7]",
    }
    function_parameters = ("$i0", "$i1", "$i2", "$i3", "$i4", "$i5")
    syscall_register = "$r0"
    syscall_instructions = ("sc",)
    ptrsize = 4


    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        # https://www.cebix.net/downloads/bebox/pem32b.pdf (% 2.1.3)
        if not val:
            reg = self.flag_register
            val = gef.arch.register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn: Instruction) -> bool:
        return False

    def is_ret(self, insn: Instruction) -> bool:
        return insn.mnemonic == "blr"

    def is_conditional_branch(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        branch_mnemos = {"beq", "bne", "ble", "blt", "bgt", "bge"}
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo = insn.mnemonic
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = gef.arch.register(self.flag_register)
        taken, reason = False, ""
        if mnemo == "beq":   taken, reason = bool(val&(1<<flags["equal[7]"])), "E"
        elif mnemo == "bne": taken, reason = val&(1<<flags["equal[7]"]) == 0, "!E"
        elif mnemo == "ble": taken, reason = bool(val&(1<<flags["equal[7]"])) or bool(val&(1<<flags["less[7]"])), "E || L"
        elif mnemo == "blt": taken, reason = bool(val&(1<<flags["less[7]"])), "L"
        elif mnemo == "bge": taken, reason = bool(val&(1<<flags["equal[7]"])) or bool(val&(1<<flags["greater[7]"])), "E || G"
        elif mnemo == "bgt": taken, reason = bool(val&(1<<flags["greater[7]"])), "G"
        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        ra = None
        if self.is_ret(insn):
            ra = gef.arch.register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        # Ref: https://developer.ibm.com/articles/l-ppc/
        _NR_mprotect = 125
        insns = [
            "addi 1, 1, -16",  # 1 = r1 = sp
            "stw 0, 0(1)",
            "stw 3, 4(1)",  # r0 = syscall_code | r3, r4, r5 = args
            "stw 4, 8(1)",
            "stw 5, 12(1)",
            f"li 0, {_NR_mprotect:d}",
            f"lis 3, {addr:#x}@h",
            f"ori 3, 3, {addr:#x}@l",
            f"lis 4, {size:#x}@h",
            f"ori 4, 4, {size:#x}@l",
            f"li 5, {perm.value:d}",
            "sc",
            "lwz 0, 0(1)",
            "lwz 3, 4(1)",
            "lwz 4, 8(1)",
            "lwz 5, 12(1)",
            "addi 1, 1, 16",
        ]
        return ";".join(insns)


class PowerPC64(PowerPC):
    aliases = ("PowerPC64", Elf.Abi.POWERPC64, "PPC64")
    arch = "PPC"
    mode = "PPC64"
    ptrsize = 8


class SPARC(Architecture):
    """ Refs:
    - https://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf
    """
    aliases = ("SPARC", Elf.Abi.SPARC)
    arch = "SPARC"
    mode = ""

    all_registers = (
        "$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
        "$o0", "$o1", "$o2", "$o3", "$o4", "$o5", "$o7",
        "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
        "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$i7",
        "$pc", "$npc", "$sp ", "$fp ", "$psr",)
    instruction_length = 4
    nop_insn = b"\x00\x00\x00\x00"  # sethi 0, %g0
    return_register = "$i0"
    flag_register: str = "$psr"
    flags_table = {
        23: "negative",
        22: "zero",
        21: "overflow",
        20: "carry",
        7: "supervisor",
        5: "trap",
    }
    function_parameters = ("$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ", "$o7 ",)
    syscall_register = "%g1"
    syscall_instructions = ("t 0x10",)

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        # https://www.gaisler.com/doc/sparcv8.pdf
        reg = self.flag_register
        if not val:
            val = gef.arch.register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn: Instruction) -> bool:
        return False

    def is_ret(self, insn: Instruction) -> bool:
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        # http://moss.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/condbranch.html
        branch_mnemos = {
            "be", "bne", "bg", "bge", "bgeu", "bgu", "bl", "ble", "blu", "bleu",
            "bneg", "bpos", "bvs", "bvc", "bcs", "bcc"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo = insn.mnemonic
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = gef.arch.register(self.flag_register)
        taken, reason = False, ""

        if mnemo == "be": taken, reason = bool(val&(1<<flags["zero"])), "Z"
        elif mnemo == "bne": taken, reason = bool(val&(1<<flags["zero"])) == 0, "!Z"
        elif mnemo == "bg": taken, reason = bool(val&(1<<flags["zero"])) == 0 and (val&(1<<flags["negative"]) == 0 or val&(1<<flags["overflow"]) == 0), "!Z && (!N || !O)"
        elif mnemo == "bge": taken, reason = val&(1<<flags["negative"]) == 0 or val&(1<<flags["overflow"]) == 0, "!N || !O"
        elif mnemo == "bgu": taken, reason = val&(1<<flags["carry"]) == 0 and val&(1<<flags["zero"]) == 0, "!C && !Z"
        elif mnemo == "bgeu": taken, reason = val&(1<<flags["carry"]) == 0, "!C"
        elif mnemo == "bl": taken, reason = bool(val&(1<<flags["negative"])) and bool(val&(1<<flags["overflow"])), "N && O"
        elif mnemo == "blu": taken, reason = bool(val&(1<<flags["carry"])), "C"
        elif mnemo == "ble": taken, reason = bool(val&(1<<flags["zero"])) or bool(val&(1<<flags["negative"]) or val&(1<<flags["overflow"])), "Z || (N || O)"
        elif mnemo == "bleu": taken, reason = bool(val&(1<<flags["carry"])) or bool(val&(1<<flags["zero"])), "C || Z"
        elif mnemo == "bneg": taken, reason = bool(val&(1<<flags["negative"])), "N"
        elif mnemo == "bpos": taken, reason = val&(1<<flags["negative"]) == 0, "!N"
        elif mnemo == "bvs": taken, reason = bool(val&(1<<flags["overflow"])), "O"
        elif mnemo == "bvc": taken, reason = val&(1<<flags["overflow"]) == 0, "!O"
        elif mnemo == "bcs": taken, reason = bool(val&(1<<flags["carry"])), "C"
        elif mnemo == "bcc": taken, reason = val&(1<<flags["carry"]) == 0, "!C"
        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        ra = None
        if self.is_ret(insn):
            ra = gef.arch.register("$o7")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        hi = (addr & 0xffff0000) >> 16
        lo = (addr & 0x0000ffff)
        _NR_mprotect = 125
        insns = ["add %sp, -16, %sp",
                 "st %g1, [ %sp ]", "st %o0, [ %sp + 4 ]",
                 "st %o1, [ %sp + 8 ]", "st %o2, [ %sp + 12 ]",
                 f"sethi  %hi({hi}), %o0",
                 f"or  %o0, {lo}, %o0",
                 "clr  %o1",
                 "clr  %o2",
                 f"mov  {_NR_mprotect}, %g1",
                 "t 0x10",
                 "ld [ %sp ], %g1", "ld [ %sp + 4 ], %o0",
                 "ld [ %sp + 8 ], %o1", "ld [ %sp + 12 ], %o2",
                 "add %sp, 16, %sp",]
        return "; ".join(insns)


class SPARC64(SPARC):
    """Refs:
    - http://math-atlas.sourceforge.net/devel/assembly/abi_sysV_sparc.pdf
    - https://cr.yp.to/2005-590/sparcv9.pdf
    """
    aliases = ("SPARC64", Elf.Abi.SPARC64)
    arch = "SPARC"
    mode = "V9"

    all_registers = [
        "$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
        "$o0", "$o1", "$o2", "$o3", "$o4", "$o5", "$o7",
        "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
        "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$i7",
        "$pc", "$npc", "$sp", "$fp", "$state", ]

    flag_register = "$state"  # sparcv9.pdf, 5.1.5.1 (ccr)
    flags_table = {
        35: "negative",
        34: "zero",
        33: "overflow",
        32: "carry",
    }

    syscall_instructions = ["t 0x6d"]

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        hi = (addr & 0xffff0000) >> 16
        lo = (addr & 0x0000ffff)
        _NR_mprotect = 125
        insns = ["add %sp, -16, %sp",
                 "st %g1, [ %sp ]", "st %o0, [ %sp + 4 ]",
                 "st %o1, [ %sp + 8 ]", "st %o2, [ %sp + 12 ]",
                 f"sethi  %hi({hi}), %o0",
                 f"or  %o0, {lo}, %o0",
                 "clr  %o1",
                 "clr  %o2",
                 f"mov  {_NR_mprotect}, %g1",
                 "t 0x6d",
                 "ld [ %sp ], %g1", "ld [ %sp + 4 ], %o0",
                 "ld [ %sp + 8 ], %o1", "ld [ %sp + 12 ], %o2",
                 "add %sp, 16, %sp",]
        return "; ".join(insns)


class MIPS(Architecture):
    aliases: Tuple[Union[str, Elf.Abi], ...] = ("MIPS", Elf.Abi.MIPS)
    arch = "MIPS"
    mode = "MIPS32"

    # https://vhouten.home.xs4all.nl/mipsel/r3000-isa.html
    all_registers = (
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
        "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$t8", "$t9", "$k0", "$k1", "$s8", "$pc", "$sp", "$hi",
        "$lo", "$fir", "$ra", "$gp", )
    instruction_length = 4
    _ptrsize = 4
    nop_insn = b"\x00\x00\x00\x00"  # sll $0,$0,0
    return_register = "$v0"
    flag_register = "$fcsr"
    flags_table = {}
    function_parameters = ("$a0", "$a1", "$a2", "$a3")
    syscall_register = "$v0"
    syscall_instructions = ("syscall",)

    def flag_register_to_human(self, val: Optional[int] = None) -> str:
        return Color.colorify("No flag register", "yellow underline")

    def is_call(self, insn: Instruction) -> bool:
        return False

    def is_ret(self, insn: Instruction) -> bool:
        return insn.mnemonic == "jr" and insn.operands[0] == "ra"

    def is_conditional_branch(self, insn: Instruction) -> bool:
        mnemo = insn.mnemonic
        branch_mnemos = {"beq", "bne", "beqz", "bnez", "bgtz", "bgez", "bltz", "blez"}
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        mnemo, ops = insn.mnemonic, insn.operands
        taken, reason = False, ""

        if mnemo == "beq":
            taken, reason = gef.arch.register(ops[0]) == gef.arch.register(ops[1]), "{0[0]} == {0[1]}".format(ops)
        elif mnemo == "bne":
            taken, reason = gef.arch.register(ops[0]) != gef.arch.register(ops[1]), "{0[0]} != {0[1]}".format(ops)
        elif mnemo == "beqz":
            taken, reason = gef.arch.register(ops[0]) == 0, "{0[0]} == 0".format(ops)
        elif mnemo == "bnez":
            taken, reason = gef.arch.register(ops[0]) != 0, "{0[0]} != 0".format(ops)
        elif mnemo == "bgtz":
            taken, reason = gef.arch.register(ops[0]) > 0, "{0[0]} > 0".format(ops)
        elif mnemo == "bgez":
            taken, reason = gef.arch.register(ops[0]) >= 0, "{0[0]} >= 0".format(ops)
        elif mnemo == "bltz":
            taken, reason = gef.arch.register(ops[0]) < 0, "{0[0]} < 0".format(ops)
        elif mnemo == "blez":
            taken, reason = gef.arch.register(ops[0]) <= 0, "{0[0]} <= 0".format(ops)
        return taken, reason

    def get_ra(self, insn: Instruction, frame: "gdb.Frame") -> Optional[int]:
        ra = None
        if self.is_ret(insn):
            ra = gef.arch.register("$ra")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr: int, size: int, perm: Permission) -> str:
        _NR_mprotect = 4125
        insns = ["addi $sp, $sp, -16",
                 "sw $v0, 0($sp)", "sw $a0, 4($sp)",
                 "sw $a3, 8($sp)", "sw $a3, 12($sp)",
                 f"li $v0, {_NR_mprotect:d}",
                 f"li $a0, {addr:d}",
                 f"li $a1, {size:d}",
                 f"li $a2, {perm.value:d}",
                 "syscall",
                 "lw $v0, 0($sp)", "lw $a1, 4($sp)",
                 "lw $a3, 8($sp)", "lw $a3, 12($sp)",
                 "addi $sp, $sp, 16",]
        return "; ".join(insns)


class MIPS64(MIPS):
    aliases = ("MIPS64",)
    arch = "MIPS"
    mode = "MIPS64"
    _ptrsize = 8

    @staticmethod
    def supports_gdb_arch(gdb_arch: str) -> Optional[bool]:
        return gdb_arch.startswith("mips") and gef.binary.e_class == Elf.Class.ELF_64_BITS


def copy_to_clipboard(data: bytes) -> None:
    """Helper function to submit data to the clipboard"""
    if sys.platform == "linux":
        xclip = which("xclip")
        prog = [xclip, "-selection", "clipboard", "-i"]
    elif sys.platform == "darwin":
        pbcopy = which("pbcopy")
        prog = [pbcopy]
    else:
        raise NotImplementedError("copy: Unsupported OS")

    with subprocess.Popen(prog, stdin=subprocess.PIPE) as p:
        p.stdin.write(data)
        p.stdin.close()
        p.wait()
    return


def use_stdtype() -> str:
    if is_32bit(): return "uint32_t"
    elif is_64bit(): return "uint64_t"
    return "uint16_t"


def use_default_type() -> str:
    if is_32bit(): return "unsigned int"
    elif is_64bit(): return "unsigned long"
    return "unsigned short"


def use_golang_type() -> str:
    if is_32bit(): return "uint32"
    elif is_64bit(): return "uint64"
    return "uint16"


def use_rust_type() -> str:
    if is_32bit(): return "u32"
    elif is_64bit(): return "u64"
    return "u16"


def to_unsigned_long(v: gdb.Value) -> int:
    """Cast a gdb.Value to unsigned long."""
    mask = (1 << 64) - 1
    return int(v.cast(gdb.Value(mask).type)) & mask


def get_path_from_info_proc() -> Optional[str]:
    for x in gdb.execute("info proc", to_string=True).splitlines():
        if x.startswith("exe = "):
            return x.split(" = ")[1].replace("'", "")
    return None


@deprecated("Use `gef.session.os`")
def get_os() -> str:
    return gef.session.os


@lru_cache()
def is_qemu() -> bool:
    if not is_remote_debug():
        return False
    response = gdb.execute("maintenance packet Qqemu.sstepbits", to_string=True, from_tty=False)
    return "ENABLE=" in response


@lru_cache()
def is_qemu_usermode() -> bool:
    if not is_qemu():
        return False
    response = gdb.execute("maintenance packet qOffsets", to_string=True, from_tty=False)
    return "Text=" in response


@lru_cache()
def is_qemu_system() -> bool:
    if not is_qemu():
        return False
    response = gdb.execute("maintenance packet qOffsets", to_string=True, from_tty=False)
    return "received: \"\"" in response


def get_filepath() -> Optional[str]:
    """Return the local absolute path of the file currently debugged."""
    if gef.session.remote:
        return str(gef.session.remote.lfile.absolute())
    if gef.session.file:
        return str(gef.session.file.absolute())
    return None


def get_function_length(sym: str) -> int:
    """Attempt to get the length of the raw bytes of a function."""
    dis = gdb.execute(f"disassemble '{sym}'", to_string=True).splitlines()
    start_addr = int(dis[1].split()[0], 16)
    end_addr = int(dis[-2].split()[0], 16)
    return end_addr - start_addr


@lru_cache()
def get_info_files() -> List[Zone]:
    """Retrieve all the files loaded by debuggee."""
    lines = gdb.execute("info files", to_string=True).splitlines()
    infos = []
    for line in lines:
        line = line.strip()
        if not line:
            break

        if not line.startswith("0x"):
            continue

        blobs = [x.strip() for x in line.split(" ")]
        addr_start = int(blobs[0], 16)
        addr_end = int(blobs[2], 16)
        section_name = blobs[4]

        if len(blobs) == 7:
            filename = blobs[6]
        else:
            filename = get_filepath()

        infos.append(Zone(section_name, addr_start, addr_end, filename))
    return infos


def process_lookup_address(address: int) -> Optional[Section]:
    """Look up for an address in memory.
    Return an Address object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    if is_x86():
        if is_in_x86_kernel(address):
            return None

    for sect in gef.memory.maps:
        if sect.page_start <= address < sect.page_end:
            return sect

    return None


@lru_cache()
def process_lookup_path(name: str, perm: Permission = Permission.ALL) -> Optional[Section]:
    """Look up for a path in the process memory mapping.
    Return a Section object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    for sect in gef.memory.maps:
        if name in sect.path and sect.permission & perm:
            return sect

    return None


@lru_cache()
def file_lookup_name_path(name: str, path: str) -> Optional[Zone]:
    """Look up a file by name and path.
    Return a Zone object if found, None otherwise."""
    for xfile in get_info_files():
        if path == xfile.filename and name == xfile.name:
            return xfile
    return None


@lru_cache()
def file_lookup_address(address: int) -> Optional[Zone]:
    """Look up for a file by its address.
    Return a Zone object if found, None otherwise."""
    for info in get_info_files():
        if info.zone_start <= address < info.zone_end:
            return info
    return None


@lru_cache()
def lookup_address(address: int) -> Address:
    """Try to find the address in the process address space.
    Return an Address object, with validity flag set based on success."""
    sect = process_lookup_address(address)
    info = file_lookup_address(address)
    if sect is None and info is None:
        # i.e. there is no info on this address
        return Address(value=address, valid=False)
    return Address(value=address, section=sect, info=info)


def xor(data: ByteString, key: str) -> bytearray:
    """Return `data` xor-ed with `key`."""
    key_raw = binascii.unhexlify(key.lstrip("0x"))
    return bytearray(x ^ y for x, y in zip(data, itertools.cycle(key_raw)))


def is_hex(pattern: str) -> bool:
    """Return whether provided string is a hexadecimal value."""
    if not pattern.lower().startswith("0x"):
        return False
    return len(pattern) % 2 == 0 and all(c in string.hexdigits for c in pattern[2:])


def continue_handler(_: "gdb.ContinueEvent") -> None:
    """GDB event handler for new object continue cases."""
    return


def hook_stop_handler(_: "gdb.StopEvent") -> None:
    """GDB event handler for stop cases."""
    reset_all_caches()
    gdb.execute("context")
    return


def new_objfile_handler(evt: Optional["gdb.NewObjFileEvent"]) -> None:
    """GDB event handler for new object file cases."""
    reset_all_caches()
    path = evt.new_objfile.filename if evt else gdb.current_progspace().filename
    try:
        if gef.session.root and path.startswith("target:"):
            # If the process is in a container, replace the "target:" prefix
            # with the actual root directory of the process.
            path = path.replace("target:", str(gef.session.root), 1)
        target = pathlib.Path(path)
        FileFormatClasses = list(filter(lambda fmtcls: fmtcls.is_valid(target), __registered_file_formats__))
        GuessedFileFormatClass : Type[FileFormat] = FileFormatClasses.pop() if len(FileFormatClasses) else Elf
        binary = GuessedFileFormatClass(target)
        if not gef.binary:
            gef.binary = binary
            reset_architecture()
        else:
            gef.session.modules.append(binary)
    except FileNotFoundError as fne:
        # Linux automatically maps the vDSO into our process, and GDB
        # will give us the string 'system-supplied DSO' as a path.
        # This is normal, so we shouldn't warn the user about it
        if "system-supplied DSO" not in path:
            warn(f"Failed to find objfile or not a valid file format: {str(fne)}")
    except RuntimeError as re:
        warn(f"Not a valid file format: {str(re)}")
    return


def exit_handler(_: "gdb.ExitedEvent") -> None:
    """GDB event handler for exit cases."""
    global gef
    # flush the caches
    reset_all_caches()

    # disconnect properly the remote session
    gef.session.qemu_mode = False
    if gef.session.remote:
        gef.session.remote.close()
        del gef.session.remote
        gef.session.remote = None
        gef.session.remote_initializing = False

    # if `autosave_breakpoints_file` setting is configured, save the breakpoints to disk
    setting = (gef.config["gef.autosave_breakpoints_file"] or "").strip()
    if not setting:
        return

    bkp_fpath = pathlib.Path(setting).expanduser().absolute()
    if bkp_fpath.exists():
        warn(f"{bkp_fpath} exists, content will be overwritten")

    with bkp_fpath.open("w") as fd:
        for bp in gdb.breakpoints():
            if not bp.enabled or not bp.is_valid:
                continue
            fd.write(f"{'t' if bp.temporary else ''}break {bp.location}\n")
    return


def memchanged_handler(_: "gdb.MemoryChangedEvent") -> None:
    """GDB event handler for mem changes cases."""
    reset_all_caches()
    return


def regchanged_handler(_: "gdb.RegisterChangedEvent") -> None:
    """GDB event handler for reg changes cases."""
    reset_all_caches()
    return


def get_terminal_size() -> Tuple[int, int]:
    """Return the current terminal size."""
    if is_debug():
        return 600, 100

    if platform.system() == "Windows":
        from ctypes import create_string_buffer, windll
        hStdErr = -12
        herr = windll.kernel32.GetStdHandle(hStdErr)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(herr, csbi)
        if res:
            _, _, _, _, _, left, top, right, bottom, _, _ = struct.unpack("hhhhHhhhhhh", csbi.raw)
            tty_columns = right - left + 1
            tty_rows = bottom - top + 1
            return tty_rows, tty_columns
        else:
            return 600, 100
    else:
        import fcntl
        import termios
        try:
            tty_rows, tty_columns = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234")) # type: ignore
            return tty_rows, tty_columns
        except OSError:
            return 600, 100


@lru_cache()
def is_64bit() -> bool:
    """Checks if current target is 64bit."""
    return gef.arch.ptrsize == 8


@lru_cache()
def is_32bit() -> bool:
    """Checks if current target is 32bit."""
    return gef.arch.ptrsize == 4


@lru_cache()
def is_x86_64() -> bool:
    """Checks if current target is x86-64"""
    return Elf.Abi.X86_64 in gef.arch.aliases


@lru_cache()
def is_x86_32():
    """Checks if current target is an x86-32"""
    return Elf.Abi.X86_32 in gef.arch.aliases


@lru_cache()
def is_x86() -> bool:
    return is_x86_32() or is_x86_64()


@lru_cache()
def is_arch(arch: Elf.Abi) -> bool:
    return arch in gef.arch.aliases


def reset_architecture(arch: Optional[str] = None) -> None:
    """Sets the current architecture.
    If an architecture is explicitly specified by parameter, try to use that one. If this fails, an `OSError`
    exception will occur.
    If no architecture is specified, then GEF will attempt to determine automatically based on the current
    ELF target. If this fails, an `OSError` exception will occur.
    """
    global gef
    arches = __registered_architectures__

    # check if the architecture is forced by parameter
    if arch:
        try:
            gef.arch = arches[arch]()
        except KeyError:
            raise OSError(f"Specified arch {arch.upper()} is not supported")
        return

    gdb_arch = get_arch()

    preciser_arch = next((a for a in arches.values() if a.supports_gdb_arch(gdb_arch)), None)
    if preciser_arch:
        gef.arch = preciser_arch()
        return

    # last resort, use the info from elf header to find it from the known architectures
    try:
        arch_name = gef.binary.e_machine if gef.binary else gdb_arch
        gef.arch = arches[arch_name]()
    except KeyError:
        raise OSError(f"CPU type is currently not supported: {get_arch()}")
    return


@lru_cache()
def cached_lookup_type(_type: str) -> Optional[gdb.Type]:
    try:
        return gdb.lookup_type(_type).strip_typedefs()
    except RuntimeError:
        return None


@deprecated("Use `gef.arch.ptrsize` instead")
def get_memory_alignment(in_bits: bool = False) -> int:
    """Try to determine the size of a pointer on this system.
    First, try to parse it out of the ELF header.
    Next, use the size of `size_t`.
    Finally, try the size of $pc.
    If `in_bits` is set to True, the result is returned in bits, otherwise in
    bytes."""
    res = cached_lookup_type("size_t")
    if res is not None:
        return res.sizeof if not in_bits else res.sizeof * 8

    try:
        return gdb.parse_and_eval("$pc").type.sizeof
    except:
        pass

    raise OSError("GEF is running under an unsupported mode")


def clear_screen(tty: str = "") -> None:
    """Clear the screen."""
    global gef
    if not tty:
        gdb.execute("shell clear -x")
        return

    # Since the tty can be closed at any time, a PermissionError exception can
    # occur when `clear_screen` is called. We handle this scenario properly
    try:
        with open(tty, "wt") as f:
            f.write("\x1b[H\x1b[J")
    except PermissionError:
        gef.ui.redirect_fd = None
        gef.config["context.redirect"] = ""
    return


def format_address(addr: int) -> str:
    """Format the address according to its size."""
    memalign_size = gef.arch.ptrsize
    addr = align_address(addr)

    if memalign_size == 4:
        return f"0x{addr:08x}"

    return f"0x{addr:016x}"


def format_address_spaces(addr: int, left: bool = True) -> str:
    """Format the address according to its size, but with spaces instead of zeroes."""
    width = gef.arch.ptrsize * 2 + 2
    addr = align_address(addr)

    if not left:
        return f"{addr:#x}".rjust(width)

    return f"{addr:#x}".ljust(width)


def align_address(address: int) -> int:
    """Align the provided address to the process's native length."""
    if gef.arch.ptrsize == 4:
        return address & 0xFFFFFFFF

    return address & 0xFFFFFFFFFFFFFFFF


def align_address_to_size(address: int, align: int) -> int:
    """Align the address to the given size."""
    return address + ((align - (address % align)) % align)


def align_address_to_page(address: int) -> int:
    """Align the address to a page."""
    a = align_address(address) >> DEFAULT_PAGE_ALIGN_SHIFT
    return a << DEFAULT_PAGE_ALIGN_SHIFT


def parse_address(address: str) -> int:
    """Parse an address and return it as an Integer."""
    if is_hex(address):
        return int(address, 16)
    return to_unsigned_long(gdb.parse_and_eval(address))


def is_in_x86_kernel(address: int) -> bool:
    address = align_address(address)
    memalign = gef.arch.ptrsize*8 - 1
    return (address >> memalign) == 0xF


def is_remote_debug() -> bool:
    """"Return True is the current debugging session is running through GDB remote session."""
    return gef.session.remote_initializing or gef.session.remote is not None


def de_bruijn(alphabet: bytes, n: int) -> Generator[str, None, None]:
    """De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib)."""
    k = len(alphabet)
    a = [0] * k * n

    def db(t: int, p: int) -> Generator[str, None, None]:
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)

            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    return db(1, 1)


def generate_cyclic_pattern(length: int, cycle: int = 4) -> bytearray:
    """Create a `length` byte bytearray of a de Bruijn cyclic pattern."""
    charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
    return bytearray(itertools.islice(de_bruijn(charset, cycle), length))


def safe_parse_and_eval(value: str) -> Optional["gdb.Value"]:
    """GEF wrapper for gdb.parse_and_eval(): this function returns None instead of raising
    gdb.error if the eval failed."""
    try:
        return gdb.parse_and_eval(value)
    except gdb.error:
        pass
    return None


@lru_cache()
def dereference(addr: int) -> Optional["gdb.Value"]:
    """GEF wrapper for gdb dereference function."""
    try:
        ulong_t = cached_lookup_type(use_stdtype()) or \
                  cached_lookup_type(use_default_type()) or \
                  cached_lookup_type(use_golang_type()) or \
                  cached_lookup_type(use_rust_type())
        unsigned_long_type = ulong_t.pointer()
        res = gdb.Value(addr).cast(unsigned_long_type).dereference()
        # GDB does lazy fetch by default so we need to force access to the value
        res.fetch_lazy()
        return res
    except gdb.MemoryError:
        pass
    return None


def gef_convenience(value: Union[str, bytes]) -> str:
    """Defines a new convenience value."""
    global gef
    var_name = f"$_gef{gef.session.convenience_vars_index:d}"
    gef.session.convenience_vars_index += 1
    if isinstance(value, str):
        gdb.execute(f"""set {var_name} = "{value}" """)
    elif isinstance(value, bytes):
        value_as_array = "{" + ", ".join(["%#.02x" % x for x in value]) + "}"
        gdb.execute(f"""set {var_name} = {value_as_array} """)
    else:
        raise TypeError
    return var_name


def parse_string_range(s: str) -> Iterator[int]:
    """Parses an address range (e.g. 0x400000-0x401000)"""
    addrs = s.split("-")
    return map(lambda x: int(x, 16), addrs)


@lru_cache()
def is_syscall(instruction: Union[Instruction,int]) -> bool:
    """Checks whether an instruction or address points to a system call."""
    if isinstance(instruction, int):
        instruction = gef_current_instruction(instruction)
    insn_str = instruction.mnemonic
    if len(instruction.operands):
        insn_str += f" {', '.join(instruction.operands)}"
    return insn_str in gef.arch.syscall_instructions


#
# Deprecated API
#

@deprecated("Use `gef.session.pie_breakpoints[num]`")
def gef_get_pie_breakpoint(num: int) -> "PieVirtualBreakpoint":
    return gef.session.pie_breakpoints[num]


@deprecated("Use `str(gef.arch.endianness)` instead")
def endian_str() -> str:
    return str(gef.arch.endianness)


@deprecated("Use `gef.config[key]`")
def get_gef_setting(name: str) -> Any:
    return gef.config[name]


@deprecated("Use `gef.config[key] = value`")
def set_gef_setting(name: str, value: Any) -> None:
    gef.config[name] = value
    return


@deprecated("Use `gef.session.pagesize`")
def gef_getpagesize() -> int:
    return gef.session.pagesize


@deprecated("Use `gef.session.canary`")
def gef_read_canary() -> Optional[Tuple[int, int]]:
    return gef.session.canary


@deprecated("Use `gef.session.pid`")
def get_pid() -> int:
    return gef.session.pid


@deprecated("Use `gef.session.file.name`")
def get_filename() -> str:
    return gef.session.file.name


@deprecated("Use `gef.heap.main_arena`")
def get_glibc_arena() -> Optional[GlibcArena]:
    return gef.heap.main_arena


@deprecated("Use `gef.arch.register(regname)`")
def get_register(regname) -> Optional[int]:
    return gef.arch.register(regname)


@deprecated("Use `gef.memory.maps`")
def get_process_maps() -> List[Section]:
    return gef.memory.maps


@deprecated("Use `reset_architecture`")
def set_arch(arch: Optional[str] = None, _: Optional[str] = None) -> None:
    return reset_architecture(arch)

#
# GDB event hooking
#

@only_if_events_supported("cont")
def gef_on_continue_hook(func: Callable[["gdb.ContinueEvent"], None]) -> None:
    gdb.events.cont.connect(func)


@only_if_events_supported("cont")
def gef_on_continue_unhook(func: Callable[["gdb.ThreadEvent"], None]) -> None:
    gdb.events.cont.disconnect(func)


@only_if_events_supported("stop")
def gef_on_stop_hook(func: Callable[["gdb.StopEvent"], None]) -> None:
    gdb.events.stop.connect(func)


@only_if_events_supported("stop")
def gef_on_stop_unhook(func: Callable[["gdb.StopEvent"], None]) -> None:
    gdb.events.stop.disconnect(func)


@only_if_events_supported("exited")
def gef_on_exit_hook(func: Callable[["gdb.ExitedEvent"], None]) -> None:
    gdb.events.exited.connect(func)


@only_if_events_supported("exited")
def gef_on_exit_unhook(func: Callable[["gdb.ExitedEvent"], None]) -> None:
    gdb.events.exited.disconnect(func)


@only_if_events_supported("new_objfile")
def gef_on_new_hook(func: Callable[["gdb.NewObjFileEvent"], None]) -> None:
    gdb.events.new_objfile.connect(func)


@only_if_events_supported("new_objfile")
def gef_on_new_unhook(func: Callable[["gdb.NewObjFileEvent"], None]) -> None:
    gdb.events.new_objfile.disconnect(func)


@only_if_events_supported("clear_objfiles")
def gef_on_unload_objfile_hook(func: Callable[["gdb.ClearObjFilesEvent"], None]) -> None:
    gdb.events.clear_objfiles.connect(func)


@only_if_events_supported("clear_objfiles")
def gef_on_unload_objfile_unhook(func: Callable[["gdb.ClearObjFilesEvent"], None]) -> None:
    gdb.events.clear_objfiles.disconnect(func)


@only_if_events_supported("memory_changed")
def gef_on_memchanged_hook(func: Callable[["gdb.MemoryChangedEvent"], None]) -> None:
    gdb.events.memory_changed.connect(func)


@only_if_events_supported("memory_changed")
def gef_on_memchanged_unhook(func: Callable[["gdb.MemoryChangedEvent"], None]) -> None:
    gdb.events.memory_changed.disconnect(func)


@only_if_events_supported("register_changed")
def gef_on_regchanged_hook(func: Callable[["gdb.RegisterChangedEvent"], None]) -> None:
    gdb.events.register_changed.connect(func)


@only_if_events_supported("register_changed")
def gef_on_regchanged_unhook(func: Callable[["gdb.RegisterChangedEvent"], None]) -> None:
    gdb.events.register_changed.disconnect(func)


#
# Virtual breakpoints
#

class PieVirtualBreakpoint:
    """PIE virtual breakpoint (not real breakpoint)."""

    def __init__(self, set_func: Callable[[int], str], vbp_num: int, addr: int) -> None:
        # set_func(base): given a base address return a
        # "set breakpoint" gdb command string
        self.set_func = set_func
        self.vbp_num = vbp_num
        # breakpoint num, 0 represents not instantiated yet
        self.bp_num = 0
        self.bp_addr = 0
        # this address might be a symbol, just to know where to break
        if isinstance(addr, int):
            self.addr: Union[int, str] = hex(addr)
        else:
            self.addr = addr
        return

    def instantiate(self, base: int) -> None:
        if self.bp_num:
            self.destroy()

        try:
            res = gdb.execute(self.set_func(base), to_string=True)
        except gdb.error as e:
            err(e)
            return

        if "Breakpoint" not in res:
            err(res)
            return
        res_list = res.split()
        self.bp_num = res_list[1]
        self.bp_addr = res_list[3]
        return

    def destroy(self) -> None:
        if not self.bp_num:
            err("Destroy PIE breakpoint not even set")
            return
        gdb.execute(f"delete {self.bp_num}")
        self.bp_num = 0
        return


#
# Breakpoints
#

class FormatStringBreakpoint(gdb.Breakpoint):
    """Inspect stack for format string."""
    def __init__(self, spec: str, num_args: int) -> None:
        super().__init__(spec, type=gdb.BP_BREAKPOINT, internal=False)
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self) -> bool:
        reset_all_caches()
        msg = []
        ptr, addr = gef.arch.get_ith_parameter(self.num_args)
        addr = lookup_address(addr)

        if not addr.valid:
            return False

        if addr.section.is_writable():
            content = gef.memory.read_cstring(addr.value)
            name = addr.info.name if addr.info else addr.section.path
            msg.append(Color.colorify("Format string helper", "yellow bold"))
            msg.append(f"Possible insecure format string: {self.location}('{ptr}' {RIGHT_ARROW} {addr.value:#x}: '{content}')")
            msg.append(f"Reason: Call to '{self.location}()' with format string argument in position "
                       f"#{self.num_args:d} is in page {addr.section.page_start:#x} ({name}) that has write permission")
            push_context_message("warn", "\n".join(msg))
            return True

        return False


class StubBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.)."""

    def __init__(self, func: str, retval: Optional[int]) -> None:
        super().__init__(func, gdb.BP_BREAKPOINT, internal=False)
        self.func = func
        self.retval = retval

        m = f"All calls to '{self.func}' will be skipped"
        if self.retval is not None:
            m += f" (with return value set to {self.retval:#x})"
        info(m)
        return

    def stop(self) -> bool:
        gdb.execute(f"return (unsigned int){self.retval:#x}")
        ok(f"Ignoring call to '{self.func}' "
           f"(setting return value to {self.retval:#x})")
        return False


class ChangePermissionBreakpoint(gdb.Breakpoint):
    """When hit, this temporary breakpoint will restore the original code, and position
    $pc correctly."""

    def __init__(self, loc: str, code: ByteString, pc: int) -> None:
        super().__init__(loc, gdb.BP_BREAKPOINT, internal=False)
        self.original_code = code
        self.original_pc = pc
        return

    def stop(self) -> bool:
        info("Restoring original context")
        gef.memory.write(self.original_pc, self.original_code, len(self.original_code))
        info("Restoring $pc")
        gdb.execute(f"set $pc = {self.original_pc:#x}")
        return True


class TraceMallocBreakpoint(gdb.Breakpoint):
    """Track allocations done with malloc() or calloc()."""

    def __init__(self, name: str) -> None:
        super().__init__(name, gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        return

    def stop(self) -> bool:
        reset_all_caches()
        _, size = gef.arch.get_ith_parameter(0)
        self.retbp = TraceMallocRetBreakpoint(size, self.name)
        return False


class TraceMallocRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to retrieve the return value of malloc()."""

    def __init__(self, size: int, name: str) -> None:
        super().__init__(gdb.newest_frame(), internal=True)
        self.size = size
        self.name = name
        self.silent = True
        return

    def stop(self) -> bool:
        if self.return_value:
            loc = int(self.return_value)
        else:
            loc = parse_address(gef.arch.return_register)

        size = self.size
        ok(f"{Color.colorify('Heap-Analysis', 'yellow bold')} - {self.name}({size})={loc:#x}")
        check_heap_overlap = gef.config["heap-analysis-helper.check_heap_overlap"]

        # pop from free-ed list if it was in it
        if gef.session.heap_freed_chunks:
            idx = 0
            for item in gef.session.heap_freed_chunks:
                addr = item[0]
                if addr == loc:
                    gef.session.heap_freed_chunks.remove(item)
                    continue
                idx += 1

        # pop from uaf watchlist
        if gef.session.heap_uaf_watchpoints:
            idx = 0
            for wp in gef.session.heap_uaf_watchpoints:
                wp_addr = wp.address
                if loc <= wp_addr < loc + size:
                    gef.session.heap_uaf_watchpoints.remove(wp)
                    wp.enabled = False
                    continue
                idx += 1

        item = (loc, size)

        if check_heap_overlap:
            # seek all the currently allocated chunks, read their effective size and check for overlap
            msg = []
            align = gef.arch.ptrsize
            for chunk_addr, _ in gef.session.heap_allocated_chunks:
                current_chunk = GlibcChunk(chunk_addr)
                current_chunk_size = current_chunk.size

                if chunk_addr <= loc < chunk_addr + current_chunk_size:
                    offset = loc - chunk_addr - 2*align
                    if offset < 0: continue # false positive, discard

                    msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                    msg.append("Possible heap overlap detected")
                    msg.append(f"Reason {RIGHT_ARROW} new allocated chunk {loc:#x} (of size {size:d}) overlaps in-used chunk {chunk_addr:#x} (of size {current_chunk_size:#x})")
                    msg.append(f"Writing {offset:d} bytes from {chunk_addr:#x} will reach chunk {loc:#x}")
                    msg.append(f"Payload example for chunk {chunk_addr:#x} (to overwrite {loc:#x} headers):")
                    msg.append("  data = 'A'*{0:d} + 'B'*{1:d} + 'C'*{1:d}".format(offset, align))
                    push_context_message("warn", "\n".join(msg))
                    return True

        # add it to alloc-ed list
        gef.session.heap_allocated_chunks.append(item)
        return False


class TraceReallocBreakpoint(gdb.Breakpoint):
    """Track re-allocations done with realloc()."""

    def __init__(self) -> None:
        super().__init__("__libc_realloc", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self) -> bool:
        _, ptr = gef.arch.get_ith_parameter(0)
        _, size = gef.arch.get_ith_parameter(1)
        self.retbp = TraceReallocRetBreakpoint(ptr, size)
        return False


class TraceReallocRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to retrieve the return value of realloc()."""

    def __init__(self, ptr: int, size: int) -> None:
        super().__init__(gdb.newest_frame(), internal=True)
        self.ptr = ptr
        self.size = size
        self.silent = True
        return

    def stop(self) -> bool:
        if self.return_value:
            newloc = int(self.return_value)
        else:
            newloc = parse_address(gef.arch.return_register)

        if newloc != self:
            ok("{} - realloc({:#x}, {})={}".format(Color.colorify("Heap-Analysis", "yellow bold"),
                                                   self.ptr, self.size,
                                                   Color.colorify(f"{newloc:#x}", "green"),))
        else:
            ok("{} - realloc({:#x}, {})={}".format(Color.colorify("Heap-Analysis", "yellow bold"),
                                                   self.ptr, self.size,
                                                   Color.colorify(f"{newloc:#x}", "red"),))

        item = (newloc, self.size)

        try:
            # check if item was in alloc-ed list
            idx = [x for x, y in gef.session.heap_allocated_chunks].index(self.ptr)
            # if so pop it out
            item = gef.session.heap_allocated_chunks.pop(idx)
        except ValueError:
            if is_debug():
                warn(f"Chunk {self.ptr:#x} was not in tracking list")
        finally:
            # add new item to alloc-ed list
            gef.session.heap_allocated_chunks.append(item)

        return False


class TraceFreeBreakpoint(gdb.Breakpoint):
    """Track calls to free() and attempts to detect inconsistencies."""

    def __init__(self) -> None:
        super().__init__("__libc_free", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self) -> bool:
        reset_all_caches()
        _, addr = gef.arch.get_ith_parameter(0)
        msg = []
        check_free_null = gef.config["heap-analysis-helper.check_free_null"]
        check_double_free = gef.config["heap-analysis-helper.check_double_free"]
        check_weird_free = gef.config["heap-analysis-helper.check_weird_free"]
        check_uaf = gef.config["heap-analysis-helper.check_uaf"]

        ok(f"{Color.colorify('Heap-Analysis', 'yellow bold')} - free({addr:#x})")
        if addr == 0:
            if check_free_null:
                msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                msg.append(f"Attempting to free(NULL) at {gef.arch.pc:#x}")
                msg.append("Reason: if NULL page is allocatable, this can lead to code execution.")
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        if addr in [x for (x, y) in gef.session.heap_freed_chunks]:
            if check_double_free:
                msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                msg.append(f"Double-free detected {RIGHT_ARROW} free({addr:#x}) is called at {gef.arch.pc:#x} but is already in the free-ed list")
                msg.append("Execution will likely crash...")
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        # if here, no error
        # 1. move alloc-ed item to free list
        try:
            # pop from alloc-ed list
            idx = [x for x, y in gef.session.heap_allocated_chunks].index(addr)
            item = gef.session.heap_allocated_chunks.pop(idx)

        except ValueError:
            if check_weird_free:
                msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                msg.append("Heap inconsistency detected:")
                msg.append(f"Attempting to free an unknown value: {addr:#x}")
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        # 2. add it to free-ed list
        gef.session.heap_freed_chunks.append(item)

        self.retbp = None
        if check_uaf:
            # 3. (opt.) add a watchpoint on pointer
            self.retbp = TraceFreeRetBreakpoint(addr)
        return False


class TraceFreeRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to track free()d values."""

    def __init__(self, addr: int) -> None:
        super().__init__(gdb.newest_frame(), internal=True)
        self.silent = True
        self.addr = addr
        return

    def stop(self) -> bool:
        reset_all_caches()
        wp = UafWatchpoint(self.addr)
        gef.session.heap_uaf_watchpoints.append(wp)
        return False


class UafWatchpoint(gdb.Breakpoint):
    """Custom watchpoints set TraceFreeBreakpoint() to monitor free()d pointers being used."""

    def __init__(self, addr: int) -> None:
        super().__init__(f"*{addr:#x}", gdb.BP_WATCHPOINT, internal=True)
        self.address = addr
        self.silent = True
        self.enabled = True
        return

    def stop(self) -> bool:
        """If this method is triggered, we likely have a UaF. Break the execution and report it."""
        reset_all_caches()
        frame = gdb.selected_frame()
        if frame.name() in ("_int_malloc", "malloc_consolidate", "__libc_calloc", ):
            return False

        # software watchpoints stop after the next statement (see
        # https://sourceware.org/gdb/onlinedocs/gdb/Set-Watchpoints.html)
        pc = gdb_get_nth_previous_instruction_address(gef.arch.pc, 2)
        insn = gef_current_instruction(pc)
        msg = []
        msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
        msg.append(f"Possible Use-after-Free in '{get_filepath()}': "
                   f"pointer {self.address:#x} was freed, but is attempted to be used at {pc:#x}")
        msg.append(f"{insn.address:#x}   {insn.mnemonic} {Color.yellowify(', '.join(insn.operands))}")
        push_context_message("warn", "\n".join(msg))
        return True


class EntryBreakBreakpoint(gdb.Breakpoint):
    """Breakpoint used internally to stop execution at the most convenient entry point."""

    def __init__(self, location: str) -> None:
        super().__init__(location, gdb.BP_BREAKPOINT, internal=True, temporary=True)
        self.silent = True
        return

    def stop(self) -> bool:
        reset_all_caches()
        return True


class NamedBreakpoint(gdb.Breakpoint):
    """Breakpoint which shows a specified name, when hit."""

    def __init__(self, location: str, name: str) -> None:
        super().__init__(spec=location, type=gdb.BP_BREAKPOINT, internal=False, temporary=False)
        self.name = name
        self.loc = location
        return

    def stop(self) -> bool:
        reset_all_caches()
        push_context_message("info", f"Hit breakpoint {self.loc} ({Color.colorify(self.name, 'red bold')})")
        return True


#
# Context Panes
#

def register_external_context_pane(pane_name: str, display_pane_function: Callable[[], None], pane_title_function: Callable[[], Optional[str]], condition : Optional[Callable[[], bool]] = None) -> None:
    """
    Registering function for new GEF Context View.
    pane_name: a string that has no spaces (used in settings)
    display_pane_function: a function that uses gef_print() to print strings
    pane_title_function: a function that returns a string or None, which will be displayed as the title.
    If None, no title line is displayed.
    condition: an optional callback: if not None, the callback will be executed first. If it returns true,
      then only the pane title and content will displayed. Otherwise, it's simply skipped.

    Example usage for a simple text to show when we hit a syscall:
    def only_syscall(): return gef_current_instruction(gef.arch.pc).is_syscall()
    def display_pane():
      gef_print("Wow, I am a context pane!")
    def pane_title():
      return "example:pane"
    register_external_context_pane("example_pane", display_pane, pane_title, only_syscall)
    """
    gef.gdb.add_context_pane(pane_name, display_pane_function, pane_title_function, condition)
    return


#
# Commands
#
@deprecated("Use `register()`, and inherit from `GenericCommand` instead")
def register_external_command(cls: Type["GenericCommand"]) -> Type["GenericCommand"]:
    """Registering function for new GEF (sub-)command to GDB."""
    return cls

@deprecated("Use `register()`, and inherit from `GenericCommand` instead")
def register_command(cls: Type["GenericCommand"]) -> Type["GenericCommand"]:
    """Decorator for registering new GEF (sub-)command to GDB."""
    return cls

@deprecated("")
def register_priority_command(cls: Type["GenericCommand"]) -> Type["GenericCommand"]:
    """Decorator for registering new command with priority, meaning that it must
    loaded before the other generic commands."""
    return cls


def register(cls: Union[Type["GenericCommand"], Type["GenericFunction"]]) -> Union[Type["GenericCommand"], Type["GenericFunction"]]:
    global __registered_commands__, __registered_functions__
    if issubclass(cls, GenericCommand):
        assert( hasattr(cls, "_cmdline_"))
        assert( hasattr(cls, "do_invoke"))
        assert( all(map(lambda x: x._cmdline_ != cls._cmdline_, __registered_commands__)))
        __registered_commands__.add(cls)
        return cls

    if issubclass(cls, GenericFunction):
        assert( hasattr(cls, "_function_"))
        assert( hasattr(cls, "invoke"))
        assert( all(map(lambda x: x._function_ != cls._function_, __registered_functions__)))
        __registered_functions__.add(cls)
        return cls

    raise TypeError(f"`{cls.__class__}` is an illegal class for `register`")


class GenericCommand(gdb.Command):
    """This is an abstract class for invoking commands, should not be instantiated."""

    _cmdline_: str
    _syntax_: str
    _example_: Union[str, List[str]] = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        attributes = ("_cmdline_", "_syntax_", )
        if not all(map(lambda x: hasattr(cls, x), attributes)):
            raise NotImplementedError

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.pre_load()
        syntax = Color.yellowify("\nSyntax: ") + self._syntax_
        example = Color.yellowify("\nExamples: \n\t")
        if isinstance(self._example_, list):
            example += "\n\t".join(self._example_)
        elif isinstance(self._example_, str):
            example += self._example_
        self.__doc__ = self.__doc__.replace(" "*4, "") + syntax + example
        self.repeat = False
        self.repeat_count = 0
        self.__last_command = None
        command_type = kwargs.setdefault("command", gdb.COMMAND_OBSCURE)
        complete_type = kwargs.setdefault("complete", gdb.COMPLETE_NONE)
        prefix = kwargs.setdefault("prefix", False)
        super().__init__(self._cmdline_, command_type, complete_type, prefix)
        self.post_load()
        return

    def invoke(self, args: str, from_tty: bool) -> None:
        try:
            argv = gdb.string_to_argv(args)
            self.__set_repeat_count(argv, from_tty)
            bufferize(self.do_invoke)(argv)
        except Exception as e:
            # Note: since we are intercepting cleaning exceptions here, commands preferably should avoid
            # catching generic Exception, but rather specific ones. This is allows a much cleaner use.
            if is_debug():
                show_last_exception()
            else:
                err(f"Command '{self._cmdline_}' failed to execute properly, reason: {e}")
        return

    def usage(self) -> None:
        err(f"Syntax\n{self._syntax_}")
        return

    def do_invoke(self, argv: List[str]) -> None:
        raise NotImplementedError

    def pre_load(self) -> None:
        return

    def post_load(self) -> None:
        return

    def __get_setting_name(self, name: str) -> str:
        clsname = self.__class__._cmdline_.replace(" ", "-")
        return f"{clsname}.{name}"

    def __iter__(self) -> Generator[str, None, None]:
        for key in gef.config.keys():
            if key.startswith(self._cmdline_):
                yield key.replace(f"{self._cmdline_}.", "", 1)

    @property
    def settings(self) -> List[str]:
        """Return the list of settings for this command."""
        return list(iter(self))

    @deprecated(f"Use `self[setting_name]` instead")
    def get_setting(self, name: str) -> Any:
        return self.__getitem__(name)

    def __getitem__(self, name: str) -> Any:
        key = self.__get_setting_name(name)
        return gef.config[key]

    @deprecated(f"Use `setting_name in self` instead")
    def has_setting(self, name: str) -> bool:
        return self.__contains__(name)

    def __contains__(self, name: str) -> bool:
        return self.__get_setting_name(name) in gef.config

    @deprecated(f"Use `self[setting_name] = value` instead")
    def add_setting(self, name: str, value: Tuple[Any, type, str], description: str = "") -> None:
        return self.__setitem__(name, (value, type(value), description))

    def __setitem__(self, name: str, value: Union[Any, Tuple[Any, str]]) -> None:
        # make sure settings are always associated to the root command (which derives from GenericCommand)
        if "GenericCommand" not in [x.__name__ for x in self.__class__.__bases__]:
            return
        key = self.__get_setting_name(name)
        if key in gef.config:
            setting = gef.config.raw_entry(key)
            setting.value = value
        else:
            if len(value) == 1:
                gef.config[key] = GefSetting(value[0])
            elif len(value) == 2:
                gef.config[key] = GefSetting(value[0], description=value[1])
        return

    @deprecated(f"Use `del self[setting_name]` instead")
    def del_setting(self, name: str) -> None:
        return self.__delitem__(name)

    def __delitem__(self, name: str) -> None:
        del gef.config[self.__get_setting_name(name)]
        return

    def __set_repeat_count(self, argv: List[str], from_tty: bool) -> None:
        if not from_tty:
            self.repeat = False
            self.repeat_count = 0
            return

        command = gdb.execute("show commands", to_string=True).strip().split("\n")[-1]
        self.repeat = self.__last_command == command
        self.repeat_count = self.repeat_count + 1 if self.repeat else 0
        self.__last_command = command
        return


@register
class VersionCommand(GenericCommand):
    """Display GEF version info."""

    _cmdline_ = "version"
    _syntax_ = f"{_cmdline_}"
    _example_ = f"{_cmdline_}"

    def do_invoke(self, argv: List[str]) -> None:
        gef_fpath = pathlib.Path(inspect.stack()[0][1]).expanduser().absolute()
        gef_dir = gef_fpath.parent
        with gef_fpath.open("rb") as f:
            gef_hash = hashlib.sha256(f.read()).hexdigest()

        if os.access(f"{gef_dir}/.git", os.X_OK):
            ver = subprocess.check_output("git log --format='%H' -n 1 HEAD", cwd=gef_dir, shell=True).decode("utf8").strip()
            extra = "dirty" if len(subprocess.check_output("git ls-files -m", cwd=gef_dir, shell=True).decode("utf8").strip()) else "clean"
            gef_print(f"GEF: rev:{ver} (Git - {extra})")
        else:
            gef_blob_hash = subprocess.check_output(f"git hash-object {gef_fpath}", shell=True).decode().strip()
            gef_print("GEF: (Standalone)")
            gef_print(f"Blob Hash({gef_fpath}): {gef_blob_hash}")
        gef_print(f"SHA256({gef_fpath}): {gef_hash}")
        gef_print(f"GDB: {gdb.VERSION}")
        py_ver = f"{sys.version_info.major:d}.{sys.version_info.minor:d}"
        gef_print(f"GDB-Python: {py_ver}")

        if "full" in argv:
            gef_print(f"Loaded commands: {', '.join(gef.gdb.loaded_command_names)}")
        return


@register
class PrintFormatCommand(GenericCommand):
    """Print bytes format in commonly used formats, such as literals in high level languages."""

    valid_formats = ("py", "c", "js", "asm", "hex", "bytearray")
    valid_bitness = (8, 16, 32, 64)

    _cmdline_ = "print-format"
    _aliases_ = ["pf",]
    _syntax_  = (f"{_cmdline_} [--lang LANG] [--bitlen SIZE] [(--length,-l) LENGTH] [--clip] LOCATION"
                 f"\t--lang LANG specifies the output format for programming language (available: {valid_formats!s}, default 'py')."
                 f"\t--bitlen SIZE specifies size of bit (possible values: {valid_bitness!s}, default is 8)."
                 "\t--length LENGTH specifies length of array (default is 256)."
                 "\t--clip The output data will be copied to clipboard"
                 "\tLOCATION specifies where the address of bytes is stored.")
    _example_ = f"{_cmdline_} --lang py -l 16 $rsp"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self["max_size_preview"] = (10, "max size preview of bytes")
        return

    @property
    def format_matrix(self) -> Dict[int, Tuple[str, str, str]]:
        # `gef.arch.endianness` is a runtime property, should not be defined as a class property
        return {
            8:  (f"{gef.arch.endianness}B", "char", "db"),
            16: (f"{gef.arch.endianness}H", "short", "dw"),
            32: (f"{gef.arch.endianness}I", "int", "dd"),
            64: (f"{gef.arch.endianness}Q", "long long", "dq"),
        }

    @only_if_gdb_running
    @parse_arguments({"location": "$pc", }, {("--length", "-l"): 256, "--bitlen": 0, "--lang": "py", "--clip": True,})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        """Default value for print-format command."""
        args: argparse.Namespace = kwargs["arguments"]
        args.bitlen = args.bitlen or gef.arch.ptrsize * 2

        valid_bitlens = self.format_matrix.keys()
        if args.bitlen not in valid_bitlens:
            err(f"Size of bit must be in: {valid_bitlens!s}")
            return

        if args.lang not in self.valid_formats:
            err(f"Language must be in: {self.valid_formats!s}")
            return

        start_addr = parse_address(args.location)
        size = int(args.bitlen / 8)
        end_addr = start_addr + args.length * size
        fmt = self.format_matrix[args.bitlen][0]
        data = []

        if args.lang != "bytearray":
            for addr in range(start_addr, end_addr, size):
                value = struct.unpack(fmt, gef.memory.read(addr, size))[0]
                data += [value]
            sdata = ", ".join(map(hex, data))
        else:
            sdata = ""

        if args.lang == "bytearray":
            data = gef.memory.read(start_addr, args.length)
            preview = str(data[0:self["max_size_preview"]])
            out = f"Saved data {preview}... in '{gef_convenience(data)}'"
        elif args.lang == "py":
            out = f"buf = [{sdata}]"
        elif args.lang == "c":
            c_type = self.format_matrix[args.bitlen][1]
            out = f"unsigned {c_type} buf[{args.length}] = {{{sdata}}};"
        elif args.lang == "js":
            out = f"var buf = [{sdata}]"
        elif args.lang == "asm":
            asm_type = self.format_matrix[args.bitlen][2]
            out = "buf {0} {1}".format(asm_type, sdata)
        elif args.lang == "hex":
            out = binascii.hexlify(gef.memory.read(start_addr, end_addr-start_addr)).decode()
        else:
            raise ValueError(f"Invalid format: {args.lang}")

        if args.clip:
            if copy_to_clipboard(gef_pybytes(out)):
                info("Copied to clipboard")
            else:
                warn("There's a problem while copying")

        gef_print(out)
        return


@register
class PieCommand(GenericCommand):
    """PIE breakpoint support."""

    _cmdline_ = "pie"
    _syntax_ = f"{_cmdline_} (breakpoint|info|delete|run|attach|remote)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            self.usage()
        return


@register
class PieBreakpointCommand(GenericCommand):
    """Set a PIE breakpoint at an offset from the target binaries base address."""

    _cmdline_ = "pie breakpoint"
    _syntax_ = f"{_cmdline_} OFFSET"

    @parse_arguments({"offset": ""}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.offset:
            self.usage()
            return

        addr = parse_address(args.offset)
        self.set_pie_breakpoint(lambda base: f"b *{base + addr}", addr)

        # When the process is already on, set real breakpoints immediately
        if is_alive():
            vmmap = gef.memory.maps
            base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
            for bp_ins in gef.session.pie_breakpoints.values():
                bp_ins.instantiate(base_address)
        return

    @staticmethod
    def set_pie_breakpoint(set_func: Callable[[int], str], addr: int) -> None:
        gef.session.pie_breakpoints[gef.session.pie_counter] = PieVirtualBreakpoint(set_func, gef.session.pie_counter, addr)
        gef.session.pie_counter += 1
        return


@register
class PieInfoCommand(GenericCommand):
    """Display breakpoint info."""

    _cmdline_ = "pie info"
    _syntax_ = f"{_cmdline_} BREAKPOINT"

    @parse_arguments({"breakpoints": [-1,]}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if args.breakpoints[0] == -1:
            # No breakpoint info needed
            bps = gef.session.pie_breakpoints.values()
        else:
            bps = [gef.session.pie_breakpoints[x]
                   for x in args.breakpoints
                   if x in gef.session.pie_breakpoints]

        lines = ["{:6s}  {:6s}  {:18s}".format("VNum","Num","Addr")]
        lines += [
            f"{x.vbp_num:6d}  {str(x.bp_num) if x.bp_num else 'N/A':6s}  {x.addr:18s}" for x in bps
        ]
        gef_print("\n".join(lines))
        return


@register
class PieDeleteCommand(GenericCommand):
    """Delete a PIE breakpoint."""

    _cmdline_ = "pie delete"
    _syntax_ = f"{_cmdline_} [BREAKPOINT]"

    @parse_arguments({"breakpoints": [-1,]}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        global gef
        args : argparse.Namespace = kwargs["arguments"]
        if args.breakpoints[0] == -1:
            # no arg, delete all
            to_delete = list(gef.session.pie_breakpoints.values())
            self.delete_bp(to_delete)
        else:
            self.delete_bp([gef.session.pie_breakpoints[x]
                            for x in args.breakpoints
                            if x in gef.session.pie_breakpoints])
        return


    @staticmethod
    def delete_bp(breakpoints: List[PieVirtualBreakpoint]) -> None:
        global gef
        for bp in breakpoints:
            # delete current real breakpoints if exists
            if bp.bp_num:
                gdb.execute(f"delete {bp.bp_num}")
            # delete virtual breakpoints
            del gef.session.pie_breakpoints[bp.vbp_num]
        return


@register
class PieRunCommand(GenericCommand):
    """Run process with PIE breakpoint support."""

    _cmdline_ = "pie run"
    _syntax_ = _cmdline_

    def do_invoke(self, argv: List[str]) -> None:
        global gef
        fpath = get_filepath()
        if not fpath:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn(f"The file '{fpath}' is not executable.")
            return

        if is_alive():
            warn("gdb is already running. Restart process.")

        # get base address
        gdb.execute("set stop-on-solib-events 1")
        hide_context()
        gdb.execute(f"run {' '.join(argv)}")
        unhide_context()
        gdb.execute("set stop-on-solib-events 0")
        vmmap = gef.memory.maps
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        info(f"base address {hex(base_address)}")

        # modify all breakpoints
        for bp_ins in gef.session.pie_breakpoints.values():
            bp_ins.instantiate(base_address)

        try:
            gdb.execute("continue")
        except gdb.error as e:
            err(e)
            gdb.execute("kill")
        return


@register
class PieAttachCommand(GenericCommand):
    """Do attach with PIE breakpoint support."""

    _cmdline_ = "pie attach"
    _syntax_ = f"{_cmdline_} PID"

    def do_invoke(self, argv: List[str]) -> None:
        try:
            gdb.execute(f"attach {' '.join(argv)}", to_string=True)
        except gdb.error as e:
            err(e)
            return
        # after attach, we are stopped so that we can
        # get base address to modify our breakpoint
        vmmap = gef.memory.maps
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]

        for bp_ins in gef.session.pie_breakpoints.values():
            bp_ins.instantiate(base_address)
        gdb.execute("context")
        return


@register
class PieRemoteCommand(GenericCommand):
    """Attach to a remote connection with PIE breakpoint support."""

    _cmdline_ = "pie remote"
    _syntax_ = f"{_cmdline_} REMOTE"

    def do_invoke(self, argv: List[str]) -> None:
        try:
            gdb.execute(f"gef-remote {' '.join(argv)}")
        except gdb.error as e:
            err(e)
            return
        # after remote attach, we are stopped so that we can
        # get base address to modify our breakpoint
        vmmap = gef.memory.maps
        base_address = [x.page_start for x in vmmap if x.realpath == get_filepath()][0]

        for bp_ins in gef.session.pie_breakpoints.values():
            bp_ins.instantiate(base_address)
        gdb.execute("context")
        return


@register
class SmartEvalCommand(GenericCommand):
    """SmartEval: Smart eval (vague approach to mimic WinDBG `?`)."""

    _cmdline_ = "$"
    _syntax_  = f"{_cmdline_} EXPR\n{_cmdline_} ADDRESS1 ADDRESS2"
    _example_ = (f"\n{_cmdline_} $pc+1"
                 f"\n{_cmdline_} 0x00007ffff7a10000 0x00007ffff7bce000")

    def do_invoke(self, argv: List[str]) -> None:
        argc = len(argv)
        if argc == 1:
            self.evaluate(argv)
            return

        if argc == 2:
            self.distance(argv)
        return

    def evaluate(self, expr: List[str]) -> None:
        def show_as_int(i: int) -> None:
            off = gef.arch.ptrsize*8
            def comp2_x(x: Any) -> str: return f"{(x + (1 << off)) % (1 << off):x}"
            def comp2_b(x: Any) -> str: return f"{(x + (1 << off)) % (1 << off):b}"

            try:
                s_i = comp2_x(res)
                s_i = s_i.rjust(len(s_i)+1, "0") if len(s_i)%2 else s_i
                gef_print(f"{i:d}")
                gef_print("0x" + comp2_x(res))
                gef_print("0b" + comp2_b(res))
                gef_print(f"{binascii.unhexlify(s_i)}")
                gef_print(f"{binascii.unhexlify(s_i)[::-1]}")
            except:
                pass
            return

        parsed_expr = []
        for xp in expr:
            try:
                xp = gdb.parse_and_eval(xp)
                xp = int(xp)
                parsed_expr.append(f"{xp:d}")
            except gdb.error:
                parsed_expr.append(str(xp))

        try:
            res = eval(" ".join(parsed_expr))
            if isinstance(res, int):
                show_as_int(res)
            else:
                gef_print(f"{res}")
        except SyntaxError:
            gef_print(" ".join(parsed_expr))
        return

    def distance(self, args: Tuple[str, str]) -> None:
        try:
            x = int(args[0], 16) if is_hex(args[0]) else int(args[0])
            y = int(args[1], 16) if is_hex(args[1]) else int(args[1])
            gef_print(f"{abs(x - y)}")
        except ValueError:
            warn(f"Distance requires 2 numbers: {self._cmdline_} 0 0xffff")
        return


@register
class CanaryCommand(GenericCommand):
    """Shows the canary value of the current process."""

    _cmdline_ = "canary"
    _syntax_ = _cmdline_

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        self.dont_repeat()

        has_canary = Elf(get_filepath()).checksec["Canary"]
        if not has_canary:
            warn("This binary was not compiled with SSP.")
            return

        res = gef.session.canary
        if not res:
            err("Failed to get the canary")
            return

        canary, location = res
        info(f"The canary of process {gef.session.pid} is at {location:#x}, value is {canary:#x}")
        return


@register
class ProcessStatusCommand(GenericCommand):
    """Extends the info given by GDB `info proc`, by giving an exhaustive description of the
    process status (file descriptors, ancestor, descendants, etc.)."""

    _cmdline_ = "process-status"
    _syntax_  = _cmdline_
    _aliases_ = ["status", ]

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_NONE)
        return

    @only_if_gdb_running
    @only_if_gdb_target_local
    def do_invoke(self, argv: List[str]) -> None:
        self.show_info_proc()
        self.show_ancestor()
        self.show_descendants()
        self.show_fds()
        self.show_connections()
        return

    def get_state_of(self, pid: int) -> Dict[str, str]:
        res = {}
        with open(f"/proc/{pid}/status", "r") as f:
            file = f.readlines()
        for line in file:
            key, value = line.split(":", 1)
            res[key.strip()] = value.strip()
        return res

    def get_cmdline_of(self, pid: int) -> str:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            return f.read().replace("\x00", "\x20").strip()

    def get_process_path_of(self, pid: int) -> str:
        return os.readlink(f"/proc/{pid}/exe")

    def get_children_pids(self, pid: int) -> List[int]:
        cmd = [gef.session.constants["ps"], "-o", "pid", "--ppid", f"{pid}", "--noheaders"]
        try:
            return [int(x) for x in gef_execute_external(cmd, as_list=True)]
        except Exception:
            return []

    def show_info_proc(self) -> None:
        info("Process Information")
        pid = gef.session.pid
        cmdline = self.get_cmdline_of(pid)
        gef_print(f"\tPID {RIGHT_ARROW} {pid}",
                  f"\tExecutable {RIGHT_ARROW} {self.get_process_path_of(pid)}",
                  f"\tCommand line {RIGHT_ARROW} '{cmdline}'", sep="\n")
        return

    def show_ancestor(self) -> None:
        info("Parent Process Information")
        ppid = int(self.get_state_of(gef.session.pid)["PPid"])
        state = self.get_state_of(ppid)
        cmdline = self.get_cmdline_of(ppid)
        gef_print(f"\tParent PID {RIGHT_ARROW} {state['Pid']}",
                  f"\tCommand line {RIGHT_ARROW} '{cmdline}'", sep="\n")
        return

    def show_descendants(self) -> None:
        info("Children Process Information")
        children = self.get_children_pids(gef.session.pid)
        if not children:
            gef_print("\tNo child process")
            return

        for child_pid in children:
            state = self.get_state_of(child_pid)
            pid = state["Pid"]
            gef_print(f"\tPID {RIGHT_ARROW} {pid} (Name: '{self.get_process_path_of(pid)}', CmdLine: '{self.get_cmdline_of(pid)}')")
            return

    def show_fds(self) -> None:
        pid = gef.session.pid
        path = f"/proc/{pid:d}/fd"

        info("File Descriptors:")
        items = os.listdir(path)
        if not items:
            gef_print("\tNo FD opened")
            return

        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath):
                gef_print(f"\t{fullpath} {RIGHT_ARROW} {os.readlink(fullpath)}")
        return

    def list_sockets(self, pid: int) -> List[int]:
        sockets = []
        path = f"/proc/{pid:d}/fd"
        items = os.listdir(path)
        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath) and os.readlink(fullpath).startswith("socket:"):
                p = os.readlink(fullpath).replace("socket:", "")[1:-1]
                sockets.append(int(p))
        return sockets

    def parse_ip_port(self, addr: str) -> Tuple[str, int]:
        ip, port = addr.split(":")
        return socket.inet_ntoa(struct.pack("<I", int(ip, 16))), int(port, 16)

    def show_connections(self) -> None:
        # https://github.com/torvalds/linux/blob/v4.7/include/net/tcp_states.h#L16
        tcp_states_str = {
            0x01: "TCP_ESTABLISHED",
            0x02: "TCP_SYN_SENT",
            0x03: "TCP_SYN_RECV",
            0x04: "TCP_FIN_WAIT1",
            0x05: "TCP_FIN_WAIT2",
            0x06: "TCP_TIME_WAIT",
            0x07: "TCP_CLOSE",
            0x08: "TCP_CLOSE_WAIT",
            0x09: "TCP_LAST_ACK",
            0x0A: "TCP_LISTEN",
            0x0B: "TCP_CLOSING",
            0x0C: "TCP_NEW_SYN_RECV",
        }

        udp_states_str = {
            0x07: "UDP_LISTEN",
        }

        info("Network Connections")
        pid = gef.session.pid
        sockets = self.list_sockets(pid)
        if not sockets:
            gef_print("\tNo open connections")
            return

        entries = dict()
        with open(f"/proc/{pid:d}/net/tcp", "r") as tcp:
            entries["TCP"] = [x.split() for x in tcp.readlines()[1:]]
        with open(f"/proc/{pid:d}/net/udp", "r") as udp:
            entries["UDP"] = [x.split() for x in udp.readlines()[1:]]

        for proto in entries:
            for entry in entries[proto]:
                local, remote, state = entry[1:4]
                inode = int(entry[9])
                if inode in sockets:
                    local = self.parse_ip_port(local)
                    remote = self.parse_ip_port(remote)
                    state = int(state, 16)
                    state_str = tcp_states_str[state] if proto == "TCP" else udp_states_str[state]

                    gef_print(f"\t{local[0]}:{local[1]} {RIGHT_ARROW} {remote[0]}:{remote[1]} ({state_str})")
        return


@register
class GefThemeCommand(GenericCommand):
    """Customize GEF appearance."""

    _cmdline_ = "theme"
    _syntax_ = f"{_cmdline_} [KEY [VALUE]]"

    def __init__(self) -> None:
        super().__init__(self._cmdline_)
        self["context_title_line"] = ("gray", "Color of the borders in context window")
        self["context_title_message"] = ("cyan", "Color of the title in context window")
        self["default_title_line"] = ("gray", "Default color of borders")
        self["default_title_message"] = ("cyan", "Default color of title")
        self["table_heading"] = ("blue", "Color of the column headings to tables (e.g. vmmap)")
        self["old_context"] = ("gray", "Color to use to show things such as code that is not immediately relevant")
        self["disassemble_current_instruction"] = ("green", "Color to use to highlight the current $pc when disassembling")
        self["dereference_string"] = ("yellow", "Color of dereferenced string")
        self["dereference_code"] = ("gray", "Color of dereferenced code")
        self["dereference_base_address"] = ("cyan", "Color of dereferenced address")
        self["dereference_register_value"] = ("bold blue", "Color of dereferenced register")
        self["registers_register_name"] = ("blue", "Color of the register name in the register window")
        self["registers_value_changed"] = ("bold red", "Color of the changed register in the register window")
        self["address_stack"] = ("pink", "Color to use when a stack address is found")
        self["address_heap"] = ("green", "Color to use when a heap address is found")
        self["address_code"] = ("red", "Color to use when a code address is found")
        self["source_current_line"] = ("green", "Color to use for the current code line in the source window")
        return

    def do_invoke(self, args: List[str]) -> None:
        self.dont_repeat()
        argc = len(args)

        if argc == 0:
            for key in self.settings:
                setting = self[key]
                value = Color.colorify(setting, setting)
                gef_print(f"{key:40s}: {value}")
            return

        setting_name = args[0]
        if not setting_name in self:
            err("Invalid key")
            return

        if argc == 1:
            value = self[setting_name]
            gef_print(f"{setting_name:40s}: {Color.colorify(value, value)}")
            return

        colors = [color for color in args[1:] if color in Color.colors]
        self[setting_name] = " ".join(colors)
        return


class ExternalStructureManager:
    class Structure:
        def __init__(self, manager: "ExternalStructureManager", mod_path: pathlib.Path, struct_name: str) -> None:
            self.manager = manager
            self.module_path = mod_path
            self.name = struct_name
            self.class_type = self.__get_structure_class()
            # if the symbol points to a class factory method and not a class
            if not hasattr(self.class_type, "_fields_") and callable(self.class_type):
                self.class_type = self.class_type(gef)
            return

        def __str__(self) -> str:
            return self.name

        def pprint(self) -> None:
            res = []
            for _name, _type in self.class_type._fields_:
                size = ctypes.sizeof(_type)
                name = Color.colorify(_name, gef.config["pcustom.structure_name"])
                type = Color.colorify(_type.__name__, gef.config["pcustom.structure_type"])
                size = Color.colorify(hex(size), gef.config["pcustom.structure_size"])
                offset = Color.boldify(f"{getattr(self.class_type, _name).offset:04x}")
                res.append(f"{offset}   {name:32s}   {type:16s}  /* size={size} */")
            gef_print("\n".join(res))
            return

        def __get_structure_class(self) -> Type:
            """Returns a tuple of (class, instance) if modname!classname exists"""
            fpath = self.module_path
            spec = importlib.util.spec_from_file_location(fpath.stem, fpath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[fpath.stem] = module
            spec.loader.exec_module(module)
            _class = getattr(module, self.name)
            return _class

        def apply_at(self, address: int, max_depth: int, depth: int = 0) -> None:
            """Apply (recursively if possible) the structure format to the given address."""
            if depth >= max_depth:
                warn("maximum recursion level reached")
                return

            # read the data at the specified address
            _structure = self.class_type()
            _sizeof_structure = ctypes.sizeof(_structure)

            try:
                data = gef.memory.read(address, _sizeof_structure)
            except gdb.MemoryError:
                err(f"{' ' * depth}Cannot read memory {address:#x}")
                return

            # deserialize the data
            length = min(len(data), _sizeof_structure)
            ctypes.memmove(ctypes.addressof(_structure), data, length)

            # pretty print all the fields (and call recursively if possible)
            ptrsize = gef.arch.ptrsize
            unpack = u32 if ptrsize == 4 else u64
            for field in _structure._fields_:
                _name, _type = field
                _value = getattr(_structure, _name)
                _offset = getattr(self.class_type, _name).offset

                if ((ptrsize == 4 and _type is ctypes.c_uint32)
                    or (ptrsize == 8 and _type is ctypes.c_uint64)
                    or (ptrsize == ctypes.sizeof(ctypes.c_void_p) and _type is ctypes.c_void_p)):
                    # try to dereference pointers
                    _value = RIGHT_ARROW.join(dereference_from(_value))

                line = f"{'  ' * depth}"
                line += f"{address:#x}+{_offset:#04x} {_name} : ".ljust(40)
                line += f"{_value} ({_type.__name__})"
                parsed_value = self.__get_ctypes_value(_structure, _name, _value)
                if parsed_value:
                    line += f"{RIGHT_ARROW} {parsed_value}"
                gef_print(line)

                if issubclass(_type, ctypes.Structure):
                    self.apply_at(address + _offset, max_depth, depth + 1)
                elif _type.__name__.startswith("LP_"):
                    # Pointer to a structure of a different type
                    __sub_type_name = _type.__name__.lstrip("LP_")
                    result = self.manager.find(__sub_type_name)
                    if result:
                        _, __structure = result
                        __address = unpack(gef.memory.read(address + _offset, ptrsize))
                        __structure.apply_at(__address, max_depth, depth + 1)
            return

        def __get_ctypes_value(self, struct, item, value) -> str:
            if not hasattr(struct, "_values_"): return ""
            default = ""
            for name, values in struct._values_:
                if name != item: continue
                if callable(values):
                    return values(value)
                try:
                    for val, desc in values:
                        if value == val: return desc
                        if val is None: default = desc
                except Exception as e:
                    err(f"Error parsing '{name}': {e}")
            return default

    class Module(dict):
        def __init__(self, manager: "ExternalStructureManager", path: pathlib.Path) -> None:
            self.manager = manager
            self.path = path
            self.name = path.stem
            self.raw = self.__load()

            for entry in self:
                structure = ExternalStructureManager.Structure(manager, self.path, entry)
                self[structure.name] = structure
            return

        def __load(self) -> ModuleType:
            """Load a custom module, and return it."""
            fpath = self.path
            spec = importlib.util.spec_from_file_location(fpath.stem, fpath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[fpath.stem] = module
            spec.loader.exec_module(module)
            return module

        def __str__(self) -> str:
            return self.name

        def __iter__(self) -> Generator[str, None, None]:
            _invalid = {"BigEndianStructure", "LittleEndianStructure", "Structure"}
            for x in dir(self.raw):
                if x in _invalid: continue
                _attr = getattr(self.raw, x)

                # if it's a ctypes.Structure class, add it
                if inspect.isclass(_attr) and issubclass(_attr, ctypes.Structure):
                    yield x
                    continue

                # also accept class factory functions
                if callable(_attr) and _attr.__module__ == self.name and x.endswith("_t"):
                    yield x
                    continue
            return

    class Modules(dict):
        def __init__(self, manager: "ExternalStructureManager") -> None:
            self.manager: "ExternalStructureManager" = manager
            self.root: pathlib.Path = manager.path

            for entry in self.root.iterdir():
                if not entry.is_file(): continue
                if entry.suffix != ".py": continue
                if entry.name == "__init__.py": continue
                module = ExternalStructureManager.Module(manager, entry)
                self[module.name] = module
            return

        def __contains__(self, structure_name: str) -> bool:
            """Return True if the structure name is found in any of the modules"""
            for module in self.values():
                if structure_name in module:
                    return True
            return False

    def __init__(self) -> None:
        self.clear_caches()
        return

    def clear_caches(self) -> None:
        self._path = None
        self._modules = None
        return

    @property
    def modules(self) -> "ExternalStructureManager.Modules":
        if not self._modules:
            self._modules = ExternalStructureManager.Modules(self)
        return self._modules

    @property
    def path(self) -> pathlib.Path:
        if not self._path:
            self._path = pathlib.Path(gef.config["pcustom.struct_path"]).expanduser().absolute()
        return self._path

    @property
    def structures(self) -> Generator[Tuple["ExternalStructureManager.Module", "ExternalStructureManager.Structure"], None, None]:
        for module in self.modules.values():
            for structure in module.values():
                yield module, structure
        return

    @lru_cache()
    def find(self, structure_name: str) -> Optional[Tuple["ExternalStructureManager.Module", "ExternalStructureManager.Structure"]]:
        """Return the module and structure for the given structure name; `None` if the structure name was not found."""
        for module in self.modules.values():
            if structure_name in module:
                return module, module[structure_name]
        return None


@register
class PCustomCommand(GenericCommand):
    """Dump user defined structure.
    This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows
    to apply structures (from symbols or custom) directly to an address.
    Custom structures can be defined in pure Python using ctypes, and should be stored
    in a specific directory, whose path must be stored in the `pcustom.struct_path`
    configuration setting."""

    _cmdline_ = "pcustom"
    _syntax_  = f"{_cmdline_} [list|edit <StructureName>|show <StructureName>]|<StructureName> 0xADDRESS]"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        self["struct_path"] = (str(pathlib.Path(gef.config["gef.tempdir"]) / "structs"), "Path to store/load the structure ctypes files")
        self["max_depth"] = (4, "Maximum level of recursion supported")
        self["structure_name"] = ("bold blue", "Color of the structure name")
        self["structure_type"] = ("bold red", "Color of the attribute type")
        self["structure_size"] = ("green", "Color of the attribute size")
        return

    @parse_arguments({"type": "", "address": ""}, {})
    def do_invoke(self, *_: Any, **kwargs: Dict[str, Any]) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.type:
            gdb.execute("pcustom list")
            return

        _, structname = self.explode_type(args.type)

        if not args.address:
            gdb.execute(f"pcustom show {structname}")
            return

        if not is_alive():
            err("Session is not active")
            return

        manager = ExternalStructureManager()
        address = parse_address(args.address)
        result = manager.find(structname)
        if not result:
            err(f"No structure named '{structname}' found")
            return

        _, structure = result
        structure.apply_at(address, self["max_depth"])
        return

    def explode_type(self, arg: str) -> Tuple[str, str]:
        modname, structname = arg.split(":", 1) if ":" in arg else (arg, arg)
        structname = structname.split(".", 1)[0] if "." in structname else structname
        return modname, structname


@register
class PCustomListCommand(PCustomCommand):
    """PCustom: list available structures"""

    _cmdline_ = "pcustom list"
    _syntax_ = f"{_cmdline_}"

    def __init__(self) -> None:
        super().__init__()
        return

    def do_invoke(self, _: List) -> None:
        """Dump the list of all the structures and their respective."""
        manager = ExternalStructureManager()
        info(f"Listing custom structures from '{manager.path}'")
        struct_color = gef.config["pcustom.structure_type"]
        filename_color = gef.config["pcustom.structure_name"]
        for module in manager.modules.values():
            __modules = ", ".join([Color.colorify(structure_name, struct_color) for structure_name in module.values()])
            __filename = Color.colorify(str(module.path), filename_color)
            gef_print(f"{RIGHT_ARROW} {__filename} ({__modules})")
        return


@register
class PCustomShowCommand(PCustomCommand):
    """PCustom: show the content of a given structure"""

    _cmdline_ = "pcustom show"
    _syntax_ = f"{_cmdline_} StructureName"
    __aliases__ = ["pcustom create", "pcustom update"]

    def __init__(self) -> None:
        super().__init__()
        return

    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) == 0:
            self.usage()
            return

        _, structname = self.explode_type(argv[0])
        manager = ExternalStructureManager()
        result = manager.find(structname)
        if result:
            _, structure = result
            structure.pprint()
        else:
            err(f"No structure named '{structname}' found")
        return


@register
class PCustomEditCommand(PCustomCommand):
    """PCustom: edit the content of a given structure"""

    _cmdline_ = "pcustom edit"
    _syntax_ = f"{_cmdline_} StructureName"
    __aliases__ = ["pcustom create", "pcustom new", "pcustom update"]

    def __init__(self) -> None:
        super().__init__()
        return

    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) == 0:
            self.usage()
            return

        modname, structname = self.explode_type(argv[0])
        self.__create_or_edit_structure(modname, structname)
        return

    def __create_or_edit_structure(self, mod_name: str, struct_name: str) -> int:
        path = pathlib.Path(gef.config["pcustom.struct_path"]).expanduser() / f"{mod_name}.py"
        if path.is_file():
            info(f"Editing '{path}'")
        else:
            ok(f"Creating '{path}' from template")
            self.__create_template(struct_name, path)

        cmd = (os.getenv("EDITOR") or "nano").split()
        cmd.append(str(path.absolute()))
        return subprocess.call(cmd)

    def __create_template(self, structname: str, fpath: pathlib.Path) -> None:
        template = f"""from ctypes import *

class {structname}(Structure):
    _fields_ = []

    _values_ = []
"""
        with fpath.open("w") as f:
            f.write(template)
        return


@register
class ChangeFdCommand(GenericCommand):
    """ChangeFdCommand: redirect file descriptor during runtime."""

    _cmdline_ = "hijack-fd"
    _syntax_ = f"{_cmdline_} FD_NUM NEW_OUTPUT"
    _example_ = f"{_cmdline_} 2 /tmp/stderr_output.txt"

    @only_if_gdb_running
    @only_if_gdb_target_local
    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) != 2:
            self.usage()
            return

        if not os.access(f"/proc/{gef.session.pid:d}/fd/{argv[0]}", os.R_OK):
            self.usage()
            return

        old_fd = int(argv[0])
        new_output = argv[1]

        if ":" in new_output:
            address = socket.gethostbyname(new_output.split(":")[0])
            port = int(new_output.split(":")[1])

            AF_INET = 2
            SOCK_STREAM = 1
            res = gdb.execute(f"""call (int)socket({AF_INET}, {SOCK_STREAM}, 0)""", to_string=True)
            new_fd = self.get_fd_from_result(res)

            # fill in memory with sockaddr_in struct contents
            # we will do this in the stack, since connect() wants a pointer to a struct
            vmmap = gef.memory.maps
            stack_addr = [entry.page_start for entry in vmmap if entry.path == "[stack]"][0]
            original_contents = gef.memory.read(stack_addr, 8)

            gef.memory.write(stack_addr, b"\x02\x00", 2)
            gef.memory.write(stack_addr + 0x2, struct.pack("<H", socket.htons(port)), 2)
            gef.memory.write(stack_addr + 0x4, socket.inet_aton(address), 4)

            info(f"Trying to connect to {new_output}")
            res = gdb.execute(f"""call (int)connect({new_fd}, {stack_addr}, {16})""", to_string=True)

            # recover stack state
            gef.memory.write(stack_addr, original_contents, 8)

            res = self.get_fd_from_result(res)
            if res == -1:
                err(f"Failed to connect to {address}:{port}")
                return

            info(f"Connected to {new_output}")
        else:
            res = gdb.execute(f"""call (int)open("{new_output}", 66, 0666)""", to_string=True)
            new_fd = self.get_fd_from_result(res)

        info(f"Opened '{new_output}' as fd #{new_fd:d}")
        gdb.execute(f"""call (int)dup2({new_fd:d}, {old_fd:d})""", to_string=True)
        info(f"Duplicated fd #{new_fd:d}{RIGHT_ARROW}#{old_fd:d}")
        gdb.execute(f"""call (int)close({new_fd:d})""", to_string=True)
        info(f"Closed extra fd #{new_fd:d}")
        ok("Success")
        return

    def get_fd_from_result(self, res: str) -> int:
        # Output example: $1 = 3
        res = gdb.execute(f"""p/d {int(res.split()[2], 0)}""", to_string=True)
        return int(res.split()[2], 0)


@register
class ScanSectionCommand(GenericCommand):
    """Search for addresses that are located in a memory mapping (haystack) that belonging
    to another (needle)."""

    _cmdline_ = "scan"
    _syntax_  = f"{_cmdline_} HAYSTACK NEEDLE"
    _aliases_ = ["lookup",]
    _example_ = f"\n{_cmdline_} stack libc"

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) != 2:
            self.usage()
            return

        haystack = argv[0]
        needle = argv[1]

        info(f"Searching for addresses in '{Color.yellowify(haystack)}' "
             f"that point to '{Color.yellowify(needle)}'")

        if haystack == "binary":
            haystack = get_filepath()

        if needle == "binary":
            needle = get_filepath()

        needle_sections = []
        haystack_sections = []

        if "0x" in haystack:
            start, end = parse_string_range(haystack)
            haystack_sections.append((start, end, ""))

        if "0x" in needle:
            start, end = parse_string_range(needle)
            needle_sections.append((start, end))

        for sect in gef.memory.maps:
            if haystack in sect.path:
                haystack_sections.append((sect.page_start, sect.page_end, os.path.basename(sect.path)))
            if needle in sect.path:
                needle_sections.append((sect.page_start, sect.page_end))

        step = gef.arch.ptrsize
        unpack = u32 if step == 4 else u64

        for hstart, hend, hname in haystack_sections:
            try:
                mem = gef.memory.read(hstart, hend - hstart)
            except gdb.MemoryError:
                continue

            for i in range(0, len(mem), step):
                target = unpack(mem[i:i+step])
                for nstart, nend in needle_sections:
                    if target >= nstart and target < nend:
                        deref = DereferenceCommand.pprint_dereferenced(hstart, int(i / step))
                        if hname != "":
                            name = Color.colorify(hname, "yellow")
                            gef_print(f"{name}: {deref}")
                        else:
                            gef_print(f" {deref}")

        return


@register
class SearchPatternCommand(GenericCommand):
    """SearchPatternCommand: search a pattern in memory. If given an hex value (starting with 0x)
    the command will also try to look for upwards cross-references to this address."""

    _cmdline_ = "search-pattern"
    _syntax_ = f"{_cmdline_} PATTERN [little|big] [section]"
    _aliases_ = ["grep", "xref"]
    _example_ = [f"{_cmdline_} AAAAAAAA",
                 f"{_cmdline_} 0x555555554000 little stack",
                 f"{_cmdline_} AAAA 0x600000-0x601000",
                 f"{_cmdline_} --regex 0x401000 0x401500 ([\\\\x20-\\\\x7E]{{2,}})(?=\\\\x00)   <-- It matchs null-end-printable(from x20-x7e) C strings (min size 2 bytes)"]

    def __init__(self) -> None:
        super().__init__()
        self["max_size_preview"] = (10, "max size preview of bytes")
        self["nr_pages_chunk"] = (0x400, "number of pages readed for each memory read chunk")
        return

    def print_section(self, section: Section) -> None:
        title = "In "
        if section.path:
            title += f"'{Color.blueify(section.path)}'"

        title += f"({section.page_start:#x}-{section.page_end:#x})"
        title += f", permission={section.permission}"
        ok(title)
        return

    def print_loc(self, loc: Tuple[int, int, str]) -> None:
        gef_print(f"""  {loc[0]:#x} - {loc[1]:#x} {RIGHT_ARROW}  "{Color.pinkify(loc[2])}" """)
        return

    def search_pattern_by_address(self, pattern: str, start_address: int, end_address: int) -> List[Tuple[int, int, Optional[str]]]:
        """Search a pattern within a range defined by arguments."""
        _pattern = gef_pybytes(pattern)
        step = self["nr_pages_chunk"] * gef.session.pagesize
        locations = []

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step

            try:
                mem = gef.memory.read(chunk_addr, chunk_size)
            except gdb.MemoryError as e:
                return []

            for match in re.finditer(_pattern, mem):
                start = chunk_addr + match.start()
                if is_ascii_string(start):
                    ustr = gef.memory.read_ascii_string(start) or ""
                    end = start + len(ustr)
                else:
                    ustr = gef_pystring(_pattern) + "[...]"
                    end = start + len(_pattern)
                locations.append((start, end, ustr))

            del mem

        return locations

    def search_binpattern_by_address(self, binpattern: bytes, start_address: int, end_address: int) -> List[Tuple[int, int, Optional[str]]]:
        """Search a binary pattern within a range defined by arguments."""

        step = self["nr_pages_chunk"] * gef.session.pagesize
        locations = []

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step

            try:
                mem = gef.memory.read(chunk_addr, chunk_size)
            except gdb.MemoryError as e:
                return []
            preview_size = self["max_size_preview"]
            for match in re.finditer(binpattern, mem):
                start = chunk_addr + match.start()
                preview = str(mem[slice(*match.span())][0:preview_size]) + "..."
                size_match = match.span()[1] - match.span()[0]
                if size_match > 0:
                    size_match -= 1
                end = start + size_match

                locations.append((start, end, preview))

            del mem

        return locations

    def search_pattern(self, pattern: str, section_name: str) -> None:
        """Search a pattern within the whole userland memory."""
        for section in gef.memory.maps:
            if not section.permission & Permission.READ: continue
            if section.path == "[vvar]": continue
            if not section_name in section.path: continue

            start = section.page_start
            end = section.page_end - 1
            old_section = None

            for loc in self.search_pattern_by_address(pattern, start, end):
                addr_loc_start = lookup_address(loc[0])
                if addr_loc_start and addr_loc_start.section:
                    if old_section != addr_loc_start.section:
                        self.print_section(addr_loc_start.section)
                        old_section = addr_loc_start.section

                self.print_loc(loc)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        argc = len(argv)
        if argc < 1:
            self.usage()
            return

        if argc > 3 and argv[0].startswith("--regex"):
            pattern = ' '.join(argv[3:])
            pattern = ast.literal_eval("b'" + pattern + "'")

            addr_start = parse_address(argv[1])
            addr_end = parse_address(argv[2])

            for loc in self.search_binpattern_by_address(pattern, addr_start, addr_end):
                self.print_loc(loc)

            return

        pattern = argv[0]
        endian = gef.arch.endianness

        if argc >= 2:
            if argv[1].lower() == "big": endian = Endianness.BIG_ENDIAN
            elif argv[1].lower() == "little": endian = Endianness.LITTLE_ENDIAN

        if is_hex(pattern):
            if endian == Endianness.BIG_ENDIAN:
                pattern = "".join(["\\x" + pattern[i:i + 2] for i in range(2, len(pattern), 2)])
            else:
                pattern = "".join(["\\x" + pattern[i:i + 2] for i in range(len(pattern) - 2, 0, -2)])

        if argc == 3:
            info(f"Searching '{Color.yellowify(pattern)}' in {argv[2]}")

            if "0x" in argv[2]:
                start, end = parse_string_range(argv[2])

                loc = lookup_address(start)
                if loc.valid:
                    self.print_section(loc.section)

                for loc in self.search_pattern_by_address(pattern, start, end):
                    self.print_loc(loc)
            else:
                section_name = argv[2]
                if section_name == "binary":
                    section_name = get_filepath() or ""

                self.search_pattern(pattern, section_name)
        else:
            info(f"Searching '{Color.yellowify(pattern)}' in memory")
            self.search_pattern(pattern, "")
        return


@register
class FlagsCommand(GenericCommand):
    """Edit flags in a human friendly way."""

    _cmdline_ = "edit-flags"
    _syntax_  = f"{_cmdline_} [(+|-|~)FLAGNAME ...]"
    _aliases_ = ["flags",]
    _example_ = (f"\n{_cmdline_}"
                 f"\n{_cmdline_} +zero # sets ZERO flag")

    def do_invoke(self, argv: List[str]) -> None:
        if not gef.arch.flag_register:
            warn(f"The architecture {gef.arch.arch}:{gef.arch.mode} doesn't have flag register.")
            return

        for flag in argv:
            if len(flag) < 2:
                continue

            action = flag[0]
            name = flag[1:].lower()

            if action not in ("+", "-", "~"):
                err(f"Invalid action for flag '{flag}'")
                continue

            if name not in gef.arch.flags_table.values():
                err(f"Invalid flag name '{flag[1:]}'")
                continue

            for off in gef.arch.flags_table:
                if gef.arch.flags_table[off] == name:
                    old_flag = gef.arch.register(gef.arch.flag_register)
                    if action == "+":
                        new_flags = old_flag | (1 << off)
                    elif action == "-":
                        new_flags = old_flag & ~(1 << off)
                    else:
                        new_flags = old_flag ^ (1 << off)

                    gdb.execute(f"set ({gef.arch.flag_register}) = {new_flags:#x}")

        gef_print(gef.arch.flag_register_to_human())
        return


@register
class RemoteCommand(GenericCommand):
    """GDB `target remote` command on steroids. This command will use the remote procfs to create
    a local copy of the execution environment, including the target binary and its libraries
    in the local temporary directory (the value by default is in `gef.config.tempdir`). Additionally, it
    will fetch all the /proc/PID/maps and loads all its information. If procfs is not available remotely, the command
    will likely fail. You can however still use the limited command provided by GDB `target remote`."""

    _cmdline_ = "gef-remote"
    _syntax_  = f"{_cmdline_} [OPTIONS] TARGET"
    _example_  = [f"{_cmdline_} localhost 1234",
                  f"{_cmdline_} --pid 6789 localhost 1234",
                  f"{_cmdline_} --qemu-user --qemu-binary /bin/debugme localhost 4444 "]

    def __init__(self) -> None:
        super().__init__(prefix=False)
        return

    @parse_arguments({"host": "", "port": 0}, {"--pid": -1, "--qemu-user": True, "--qemu-binary": ""})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        if gef.session.remote is not None:
            err("You already are in remote session. Close it first before opening a new one...")
            return

        # argument check
        args : argparse.Namespace = kwargs["arguments"]
        if not args.host or not args.port:
            err("Missing parameters")
            return

        # qemu-user support
        qemu_binary: Optional[pathlib.Path] = None
        if args.qemu_user:
            try:
                qemu_binary = pathlib.Path(args.qemu_binary).expanduser().absolute() if args.qemu_binary else gef.session.file
                if not qemu_binary or not qemu_binary.exists():
                    raise FileNotFoundError(f"{qemu_binary} does not exist")
            except Exception as e:
                err(f"Failed to initialize qemu-user mode, reason: {str(e)}")
                return

        # Try to establish the remote session, throw on error
        # Set `.remote_initializing` to True here - `GefRemoteSessionManager` invokes code which
        # calls `is_remote_debug` which checks if `remote_initializing` is True or `.remote` is None
        # This prevents some spurious errors being thrown during startup
        gef.session.remote_initializing = True
        gef.session.remote = GefRemoteSessionManager(args.host, args.port, args.pid, qemu_binary)
        gef.session.remote_initializing = False
        reset_all_caches()
        gdb.execute("context")
        return


@register
class SkipiCommand(GenericCommand):
    """Skip N instruction(s) execution"""

    _cmdline_ = "skipi"
    _syntax_  = ("{_cmdline_} [LOCATION] [--n NUM_INSTRUCTIONS]"
                "\n\tLOCATION\taddress/symbol from where to skip"
                 "\t--n NUM_INSTRUCTIONS\tSkip the specified number of instructions instead of the default 1.")

    _example_ = [f"{_cmdline_}",
                 f"{_cmdline_} --n 3",
                 f"{_cmdline_} 0x69696969",
                 f"{_cmdline_} 0x69696969 --n 6",]

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    @parse_arguments({"address": "$pc"}, {"--n": 1})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        address = parse_address(args.address)
        num_instructions = args.n

        last_insn = gef_instruction_n(address, num_instructions-1)
        total_bytes = (last_insn.address - address) + last_insn.size()
        target_addr  = address + total_bytes

        info(f"skipping {num_instructions} instructions ({total_bytes} bytes) from {address:#x} to {target_addr:#x}")
        gdb.execute(f"set $pc = {target_addr:#x}")
        return


@register
class NopCommand(GenericCommand):
    """Patch the instruction(s) pointed by parameters with NOP. Note: this command is architecture
    aware."""

    _cmdline_ = "nop"
    _syntax_  = ("{_cmdline_} [LOCATION] [--i ITEMS] [--f] [--n] [--b]"
                 "\n\tLOCATION\taddress/symbol to patch (by default this command replaces whole instructions)"
                 "\t--i ITEMS\tnumber of items to insert (default 1)"
                 "\t--f\tForce patch even when the selected settings could overwrite partial instructions"
                 "\t--n\tInstead of replacing whole instructions, insert ITEMS nop instructions, no matter how many instructions it overwrites"
                 "\t--b\tInstead of replacing whole instructions, fill ITEMS bytes with nops")
    _example_ = [f"{_cmdline_}",
                 f"{_cmdline_} $pc+3",
                 f"{_cmdline_} --i 2 $pc+3",
                 f"{_cmdline_} --b",
                 f"{_cmdline_} --b $pc+3",
                 f"{_cmdline_} --f --b --i 2 $pc+3"
                 f"{_cmdline_} --n --i 2 $pc+3",]

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    @parse_arguments({"address": "$pc"}, {"--i": 1, "--b": True, "--f": True, "--n": True})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        address = parse_address(args.address)
        nop = gef.arch.nop_insn
        num_items = int(args.i) or 1
        fill_bytes = bool(args.b)
        fill_nops = bool(args.n)
        force_flag = bool(args.f) or False

        if fill_nops and fill_bytes:
            err("--b and --n cannot be specified at the same time.")
            return

        total_bytes = 0
        if fill_bytes:
            total_bytes = num_items
        elif fill_nops:
            total_bytes = num_items * len(nop)
        else:
            try:
                last_insn = gef_instruction_n(address, num_items-1)
                last_addr = last_insn.address
            except:
                err(f"Cannot patch instruction at {address:#x} reaching unmapped area")
                return
            total_bytes = (last_addr - address) + gef_get_instruction_at(last_addr).size()

        if len(nop) > total_bytes or total_bytes % len(nop):
            warn(f"Patching {total_bytes} bytes at {address:#x} will result in LAST-NOP "
                 f"(byte nr {total_bytes % len(nop):#x}) broken and may cause a crash or "
                 "break disassembly.")
            if not force_flag:
                warn("Use --f (force) to ignore this warning.")
                return

        target_end_address = address + total_bytes
        curr_ins = gef_current_instruction(address)
        while curr_ins.address + curr_ins.size() < target_end_address:
            if not Address(value=curr_ins.address + 1).valid:
                err(f"Cannot patch instruction at {address:#x}: reaching unmapped area")
                return
            curr_ins = gef_next_instruction(curr_ins.address)

        final_ins_end_addr = curr_ins.address + curr_ins.size()

        if final_ins_end_addr != target_end_address:
            warn(f"Patching {total_bytes} bytes at {address:#x} will result in LAST-INSTRUCTION "
                 f"({curr_ins.address:#x}) being partial overwritten and may cause a crash or "
                 "break disassembly.")
            if not force_flag:
                warn("Use --f (force) to ignore this warning.")
                return

        nops = bytearray(nop * total_bytes)
        end_address = Address(value=address + total_bytes - 1)
        if not end_address.valid:
            err(f"Cannot patch instruction at {address:#x}: reaching unmapped "
                f"area: {end_address:#x}")
            return

        ok(f"Patching {total_bytes} bytes from {address:#x}")
        gef.memory.write(address, nops, total_bytes)

        return


@register
class StubCommand(GenericCommand):
    """Stub out the specified function. This function is useful when needing to skip one
    function to be called and disrupt your runtime flow (ex. fork)."""

    _cmdline_ = "stub"
    _syntax_  = (f"{_cmdline_} [--retval RETVAL] [address]"
                 "\taddress\taddress/symbol to stub out"
                 "\t--retval RETVAL\tSet the return value")
    _example_ = f"{_cmdline_} --retval 0 fork"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    @parse_arguments({"address": ""}, {("-r", "--retval"): 0})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        loc = args.address if args.address else f"*{gef.arch.pc:#x}"
        StubBreakpoint(loc, args.retval)
        return


@register
class GlibcHeapCommand(GenericCommand):
    """Base command to get information about the Glibc heap structure."""

    _cmdline_ = "heap"
    _syntax_  = f"{_cmdline_} (chunk|chunks|bins|arenas|set-arena)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        self.usage()
        return


@register
class GlibcHeapSetArenaCommand(GenericCommand):
    """Set the address of the main_arena or the currently selected arena."""

    _cmdline_ = "heap set-arena"
    _syntax_  = f"{_cmdline_} [address|&symbol]"
    _example_ = f"{_cmdline_} 0x001337001337"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    @parse_arguments({"addr": ""}, {"--reset": True})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        global gef

        args: argparse.Namespace = kwargs["arguments"]

        if args.reset:
            gef.heap.reset_caches()
            return

        if not args.addr:
            ok(f"Current arena set to: '{gef.heap.selected_arena}'")
            return

        try:
            new_arena_address = parse_address(args.addr)
        except gdb.error:
            err("Invalid symbol for arena")
            return

        new_arena = GlibcArena( f"*{new_arena_address:#x}")
        if new_arena in gef.heap.arenas:
            # if entered arena is in arena list then just select it
            gef.heap.selected_arena = new_arena
        else:
            # otherwise set the main arena to the entered arena
            gef.heap.main_arena = new_arena
        return


@register
class GlibcHeapArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap arenas"
    _syntax_  = _cmdline_

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        for arena in gef.heap.arenas:
            gef_print(str(arena))
        return


@register
class GlibcHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk.
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _cmdline_ = "heap chunk"
    _syntax_  = f"{_cmdline_} [-h] [--allow-unaligned] [--number] address"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"address": ""}, {"--allow-unaligned": True, "--number": 1})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.address:
            err("Missing chunk address")
            self.usage()
            return

        addr = parse_address(args.address)
        current_chunk = GlibcChunk(addr, allow_unaligned=args.allow_unaligned)

        if args.number > 1:
            for _i in range(args.number):
                if current_chunk.size == 0:
                    break

                gef_print(str(current_chunk))
                next_chunk_addr = current_chunk.get_next_chunk_addr()
                if not Address(value=next_chunk_addr).valid:
                    break

                next_chunk = current_chunk.get_next_chunk()
                if next_chunk is None:
                    break

                current_chunk = next_chunk
        else:
            gef_print(current_chunk.psprint())
        return


@register
class GlibcHeapChunksCommand(GenericCommand):
    """Display all heap chunks for the current arena. As an optional argument
    the base address of a different arena can be passed"""

    _cmdline_ = "heap chunks"
    _syntax_  = f"{_cmdline_} [-h] [--all] [--allow-unaligned] [arena_address]"
    _example_ = (f"\n{_cmdline_}"
                 f"\n{_cmdline_} 0x555555775000")

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self["peek_nb_byte"] = (16, "Hexdump N first byte(s) inside the chunk data (0 to disable)")
        return

    @parse_arguments({"arena_address": ""}, {("--all", "-a"): True, "--allow-unaligned": True})
    @only_if_gdb_running
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args = kwargs["arguments"]
        if args.all or not args.arena_address:
            for arena in gef.heap.arenas:
                self.dump_chunks_arena(arena, print_arena=args.all, allow_unaligned=args.allow_unaligned)
                if not args.all:
                    return
        try:
            arena_addr = parse_address(args.arena_address)
            arena = GlibcArena(f"*{arena_addr:#x}")
            self.dump_chunks_arena(arena, allow_unaligned=args.allow_unaligned)
        except gdb.error:
            err("Invalid arena")
            return

    def dump_chunks_arena(self, arena: GlibcArena, print_arena: bool = False, allow_unaligned: bool = False) -> None:
        heap_addr = arena.heap_addr(allow_unaligned=allow_unaligned)
        if heap_addr is None:
            err("Could not find heap for arena")
            return
        if print_arena:
            gef_print(str(arena))
        if arena.is_main_arena():
            heap_end = arena.top + GlibcChunk(arena.top, from_base=True).size
            self.dump_chunks_heap(heap_addr, heap_end, arena, allow_unaligned=allow_unaligned)
        else:
            heap_info_structs = arena.get_heap_info_list() or []
            for heap_info in heap_info_structs:
                if not self.dump_chunks_heap(heap_info.heap_start, heap_info.heap_end, arena, allow_unaligned=allow_unaligned):
                    break
        return

    def dump_chunks_heap(self, start: int, end: int, arena: GlibcArena, allow_unaligned: bool = False) -> bool:
        nb = self["peek_nb_byte"]
        chunk_iterator = GlibcChunk(start, from_base=True, allow_unaligned=allow_unaligned)
        for chunk in chunk_iterator:
            if chunk.base_address == arena.top:
                gef_print(
                    f"{chunk!s} {LEFT_ARROW} {Color.greenify('top chunk')}")
                break

            if chunk.base_address > end:
                err("Corrupted heap, cannot continue.")
                return False

            line = str(chunk)
            if nb:
                line += f"\n    [{hexdump(gef.memory.read(chunk.data_address, nb), nb, base=chunk.data_address)}]"
            gef_print(line)
        return True


@register
class GlibcHeapBinsCommand(GenericCommand):
    """Display information on the bins on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _bin_types_ = ("tcache", "fast", "unsorted", "small", "large")
    _cmdline_ = "heap bins"
    _syntax_ = f"{_cmdline_} [{'|'.join(_bin_types_)}]"

    def __init__(self) -> None:
        super().__init__(prefix=True, complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            for bin_t in self._bin_types_:
                gdb.execute(f"heap bins {bin_t}")
            return

        bin_t = argv[0]
        if bin_t not in self._bin_types_:
            self.usage()
            return

        gdb.execute(f"heap bins {bin_t}")
        return

    @staticmethod
    def pprint_bin(arena_addr: str, index: int, _type: str = "") -> int:
        arena = GlibcArena(arena_addr)

        fd, bk = arena.bin(index)
        if (fd, bk) == (0x00, 0x00):
            warn("Invalid backward and forward bin pointers(fw==bk==NULL)")
            return -1

        if _type == "tcache":
            chunkClass = GlibcTcacheChunk
        elif _type == "fast":
            chunkClass = GlibcFastChunk
        else:
            chunkClass = GlibcChunk

        nb_chunk = 0
        head = chunkClass(bk, from_base=True).fd
        if fd == head:
            return nb_chunk

        ok(f"{_type}bins[{index:d}]: fw={fd:#x}, bk={bk:#x}")

        m = []
        while fd != head:
            chunk = chunkClass(fd, from_base=True)
            m.append(f"{RIGHT_ARROW}  {chunk!s}")
            fd = chunk.fd
            nb_chunk += 1

        if m:
            gef_print("  ".join(m))
        return nb_chunk


@register
class GlibcHeapTcachebinsCommand(GenericCommand):
    """Display information on the Tcachebins on an arena (default: main_arena).
    See https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc."""

    _cmdline_ = "heap bins tcache"
    _syntax_  = f"{_cmdline_} [all] [thread_ids...]"

    TCACHE_MAX_BINS = 0x40

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        # Determine if we are using libc with tcache built in (2.26+)
        if gef.libc.version and gef.libc.version < (2, 26):
            info("No Tcache in this version of libc")
            return

        current_thread = gdb.selected_thread()
        if current_thread is None:
            err("Couldn't find current thread")
            return

        # As a nicety, we want to display threads in ascending order by gdb number
        threads = sorted(gdb.selected_inferior().threads(), key=lambda t: t.num)
        if argv:
            if "all" in argv:
                tids = [t.num for t in threads]
            else:
                tids = self.check_thread_ids([int(a) for a in argv])
        else:
            tids = [current_thread.num]

        for thread in threads:
            if thread.num not in tids:
                continue

            thread.switch()

            tcache_addr = self.find_tcache()
            if tcache_addr == 0:
                info(f"Uninitialized tcache for thread {thread.num:d}")
                continue

            gef_print(titlify(f"Tcachebins for thread {thread.num:d}"))
            tcache_empty = True
            for i in range(self.TCACHE_MAX_BINS):
                chunk, count = self.tcachebin(tcache_addr, i)
                chunks = set()
                msg = []
                chunk_size = 0

                # Only print the entry if there are valid chunks. Don't trust count
                while True:
                    if chunk is None:
                        break

                    try:
                        msg.append(f"{LEFT_ARROW} {chunk!s} ")
                        if not chunk_size:
                            chunk_size = chunk.usable_size

                        if chunk.data_address in chunks:
                            msg.append(f"{RIGHT_ARROW} [loop detected]")
                            break

                        chunks.add(chunk.data_address)

                        next_chunk = chunk.fd
                        if next_chunk == 0:
                            break

                        chunk = GlibcTcacheChunk(next_chunk)
                    except gdb.MemoryError:
                        msg.append(f"{LEFT_ARROW} [Corrupted chunk at {chunk.data_address:#x}]")
                        break

                if msg:
                    tcache_empty = False
                    tidx = gef.heap.csize2tidx(chunk_size)
                    size = gef.heap.tidx2size(tidx)
                    count = len(chunks)
                    gef_print(f"Tcachebins[idx={tidx:d}, size={size:#x}, count={count}]", end="")
                    gef_print("".join(msg))

            if tcache_empty:
                gef_print("All tcachebins are empty")

        current_thread.switch()
        return

    @staticmethod
    def find_tcache() -> int:
        """Return the location of the current thread's tcache."""
        try:
            # For multithreaded binaries, the tcache symbol (in thread local
            # storage) will give us the correct address.
            tcache_addr = parse_address("(void *) tcache")
        except gdb.error:
            # In binaries not linked with pthread (and therefore there is only
            # one thread), we can't use the tcache symbol, but we can guess the
            # correct address because the tcache is consistently the first
            # allocation in the main arena.
            heap_base = gef.heap.base_address
            if heap_base is None:
                err("No heap section")
                return 0x0
            tcache_addr = heap_base + 0x10
        return tcache_addr

    @staticmethod
    def check_thread_ids(tids: List[int]) -> List[int]:
        """Return the subset of tids that are currently valid."""
        existing_tids = set(t.num for t in gdb.selected_inferior().threads())
        return list(set(tids) & existing_tids)

    @staticmethod
    def tcachebin(tcache_base: int, i: int) -> Tuple[Optional[GlibcTcacheChunk], int]:
        """Return the head chunk in tcache[i] and the number of chunks in the bin."""
        if i >= GlibcHeapTcachebinsCommand.TCACHE_MAX_BINS:
            err("Incorrect index value, index value must be between 0 and {}-1, given {}".format(GlibcHeapTcachebinsCommand.TCACHE_MAX_BINS, i))
            return None, 0

        tcache_chunk = GlibcTcacheChunk(tcache_base)

        # Glibc changed the size of the tcache in version 2.30; this fix has
        # been backported inconsistently between distributions. We detect the
        # difference by checking the size of the allocated chunk for the
        # tcache.
        # Minimum usable size of allocated tcache chunk = ?
        #   For new tcache:
        #   TCACHE_MAX_BINS * _2_ + TCACHE_MAX_BINS * ptrsize
        #   For old tcache:
        #   TCACHE_MAX_BINS * _1_ + TCACHE_MAX_BINS * ptrsize
        new_tcache_min_size = (
                GlibcHeapTcachebinsCommand.TCACHE_MAX_BINS * 2 +
                GlibcHeapTcachebinsCommand.TCACHE_MAX_BINS * gef.arch.ptrsize)

        if tcache_chunk.usable_size < new_tcache_min_size:
            tcache_count_size = 1
            count = ord(gef.memory.read(tcache_base + tcache_count_size*i, 1))
        else:
            tcache_count_size = 2
            count = u16(gef.memory.read(tcache_base + tcache_count_size*i, 2))

        chunk = dereference(tcache_base + tcache_count_size*GlibcHeapTcachebinsCommand.TCACHE_MAX_BINS + i*gef.arch.ptrsize)
        chunk = GlibcTcacheChunk(int(chunk)) if chunk else None
        return chunk, count


@register
class GlibcHeapFastbinsYCommand(GenericCommand):
    """Display information on the fastbinsY on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _cmdline_ = "heap bins fast"
    _syntax_  = f"{_cmdline_} [ARENA_ADDRESS]"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"arena_address": ""}, {})
    @only_if_gdb_running
    def do_invoke(self, *_: Any, **kwargs: Any) -> None:
        def fastbin_index(sz: int) -> int:
            return (sz >> 4) - 2 if SIZE_SZ == 8 else (sz >> 3) - 2

        args : argparse.Namespace = kwargs["arguments"]
        if not gef.heap.main_arena:
            err("Heap not initialized")
            return

        SIZE_SZ = gef.arch.ptrsize
        MAX_FAST_SIZE = 80 * SIZE_SZ // 4
        NFASTBINS = fastbin_index(MAX_FAST_SIZE) - 1

        arena = GlibcArena(f"*{args.arena_address}") if args.arena_address else gef.heap.selected_arena
        if arena is None:
            err("Invalid Glibc arena")
            return

        gef_print(titlify(f"Fastbins for arena at {arena.addr:#x}"))
        for i in range(NFASTBINS):
            gef_print(f"Fastbins[idx={i:d}, size={(i+2)*SIZE_SZ*2:#x}] ", end="")
            chunk = arena.fastbin(i)
            chunks = set()

            while True:
                if chunk is None:
                    gef_print("0x00", end="")
                    break

                try:
                    gef_print(f"{LEFT_ARROW} {chunk!s} ", end="")
                    if chunk.data_address in chunks:
                        gef_print(f"{RIGHT_ARROW} [loop detected]", end="")
                        break

                    if fastbin_index(chunk.size) != i:
                        gef_print("[incorrect fastbin_index] ", end="")

                    chunks.add(chunk.data_address)

                    next_chunk = chunk.fd
                    if next_chunk == 0:
                        break

                    chunk = GlibcFastChunk(next_chunk, from_base=True)
                except gdb.MemoryError:
                    gef_print(f"{LEFT_ARROW} [Corrupted chunk at {chunk.data_address:#x}]", end="")
                    break
            gef_print()
        return


@register
class GlibcHeapUnsortedBinsCommand(GenericCommand):
    """Display information on the Unsorted Bins of an arena (default: main_arena).
    See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689."""

    _cmdline_ = "heap bins unsorted"
    _syntax_  = f"{_cmdline_} [ARENA_ADDRESS]"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"arena_address": ""}, {})
    @only_if_gdb_running
    def do_invoke(self, *_: Any, **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if gef.heap.main_arena is None:
            err("Heap not initialized")
            return
        arena_addr = args.arena_address if args.arena_address else f"{gef.heap.selected_arena.addr:#x}"
        gef_print(titlify(f"Unsorted Bin for arena at {arena_addr}"))
        nb_chunk = GlibcHeapBinsCommand.pprint_bin(f"*{arena_addr}", 0, "unsorted_")
        if nb_chunk >= 0:
            info(f"Found {nb_chunk:d} chunks in unsorted bin.")
        return


@register
class GlibcHeapSmallBinsCommand(GenericCommand):
    """Convenience command for viewing small bins."""

    _cmdline_ = "heap bins small"
    _syntax_  = f"{_cmdline_} [ARENA_ADDRESS]"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"arena_address": ""}, {})
    @only_if_gdb_running
    def do_invoke(self, *_: Any, **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not gef.heap.main_arena:
            err("Heap not initialized")
            return

        arena_address = args.arena_address or f"{gef.heap.selected_arena.address:#x}"
        gef_print(titlify(f"Small Bins for arena at {arena_address}"))
        bins = {}
        for i in range(1, 63):
            nb_chunk = GlibcHeapBinsCommand.pprint_bin(f"*{arena_address}", i, "small_")
            if nb_chunk < 0:
                break
            if nb_chunk > 0:
                bins[i] = nb_chunk
        info(f"Found {sum(bins.values()):d} chunks in {len(bins):d} small non-empty bins.")
        return


@register
class GlibcHeapLargeBinsCommand(GenericCommand):
    """Convenience command for viewing large bins."""

    _cmdline_ = "heap bins large"
    _syntax_  = f"{_cmdline_} [ARENA_ADDRESS]"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({"arena_address": ""}, {})
    @only_if_gdb_running
    def do_invoke(self, *_: Any, **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if gef.heap.main_arena is None:
            err("Heap not initialized")
            return

        arena_addr = args.arena_address if args.arena_address else f"{gef.heap.selected_arena.addr:#x}"
        gef_print(titlify(f"Large Bins for arena at {arena_addr}"))
        bins = {}
        for i in range(63, 126):
            nb_chunk = GlibcHeapBinsCommand.pprint_bin(f"*{arena_addr}", i, "large_")
            if nb_chunk < 0:
                break
            if nb_chunk > 0:
                bins[i] = nb_chunk
        info(f"Found {sum(bins.values()):d} chunks in {len(bins):d} large non-empty bins.")
        return


@register
class SolveKernelSymbolCommand(GenericCommand):
    """Solve kernel symbols from kallsyms table."""

    _cmdline_ = "ksymaddr"
    _syntax_  = f"{_cmdline_} SymbolToSearch"
    _example_ = f"{_cmdline_} prepare_creds"

    @parse_arguments({"symbol": ""}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        def hex_to_int(num):
            try:
                return int(num, 16)
            except ValueError:
                return 0
        args : argparse.Namespace = kwargs["arguments"]
        if not args.symbol:
            self.usage()
            return
        sym = args.symbol
        with open("/proc/kallsyms", "r") as f:
            syms = [line.strip().split(" ", 2) for line in f]
        matches = [(hex_to_int(addr), sym_t, " ".join(name.split())) for addr, sym_t, name in syms if sym in name]
        for addr, sym_t, name in matches:
            if sym == name.split()[0]:
                ok(f"Found matching symbol for '{name}' at {addr:#x} (type={sym_t})")
            else:
                warn(f"Found partial match for '{sym}' at {addr:#x} (type={sym_t}): {name}")
        if not matches:
            err(f"No match for '{sym}'")
        elif matches[0][0] == 0:
            err("Check that you have the correct permissions to view kernel symbol addresses")
        return


@register
class DetailRegistersCommand(GenericCommand):
    """Display full details on one, many or all registers value from current architecture."""

    _cmdline_ = "registers"
    _syntax_  = f"{_cmdline_} [[Register1][Register2] ... [RegisterN]]"
    _example_ = (f"\n{_cmdline_}"
                 f"\n{_cmdline_} $eax $eip $esp")

    @only_if_gdb_running
    @parse_arguments({"registers": [""]}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        unchanged_color = gef.config["theme.registers_register_name"]
        changed_color = gef.config["theme.registers_value_changed"]
        string_color = gef.config["theme.dereference_string"]
        regs = gef.arch.all_registers

        args : argparse.Namespace = kwargs["arguments"]
        if args.registers and args.registers[0]:
            all_regs = set(gef.arch.all_registers)
            regs = [reg for reg in args.registers if reg in all_regs]
            invalid_regs = [reg for reg in args.registers if reg not in all_regs]
            if invalid_regs:
                err(f"invalid registers for architecture: {', '.join(invalid_regs)}")

        memsize = gef.arch.ptrsize
        endian = str(gef.arch.endianness)
        charset = string.printable
        widest = max(map(len, gef.arch.all_registers))
        special_line = ""

        for regname in regs:
            reg = gdb.parse_and_eval(regname)
            if reg.type.code == gdb.TYPE_CODE_VOID:
                continue

            padreg = regname.ljust(widest, " ")

            if str(reg) == "<unavailable>":
                gef_print(f"{Color.colorify(padreg, unchanged_color)}: "
                          f"{Color.colorify('no value', 'yellow underline')}")
                continue

            value = align_address(int(reg))
            old_value = ContextCommand.old_registers.get(regname, 0)
            if value == old_value:
                color = unchanged_color
            else:
                color = changed_color

            # Special (e.g. segment) registers go on their own line
            if regname in gef.arch.special_registers:
                special_line += f"{Color.colorify(regname, color)}: "
                special_line += f"{gef.arch.register(regname):#04x} "
                continue

            line = f"{Color.colorify(padreg, color)}: "

            if regname == gef.arch.flag_register:
                line += gef.arch.flag_register_to_human()
                gef_print(line)
                continue

            addr = lookup_address(align_address(int(value)))
            if addr.valid:
                line += str(addr)
            else:
                line += format_address_spaces(value)
            addrs = dereference_from(value)

            if len(addrs) > 1:
                sep = f" {RIGHT_ARROW} "
                line += sep
                line += sep.join(addrs[1:])

            # check to see if reg value is ascii
            try:
                fmt = f"{endian}{'I' if memsize == 4 else 'Q'}"
                last_addr = int(addrs[-1], 16)
                val = gef_pystring(struct.pack(fmt, last_addr))
                if all([_ in charset for _ in val]):
                    line += f" (\"{Color.colorify(val, string_color)}\"?)"
            except ValueError:
                pass

            gef_print(line)

        if special_line:
            gef_print(special_line)
        return


@register
class ShellcodeCommand(GenericCommand):
    """ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to
    download shellcodes."""

    _cmdline_ = "shellcode"
    _syntax_  = f"{_cmdline_} (search|get)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    def do_invoke(self, _: List[str]) -> None:
        err("Missing sub-command (search|get)")
        self.usage()
        return


@register
class ShellcodeSearchCommand(GenericCommand):
    """Search pattern in shell-storm's shellcode database."""

    _cmdline_ = "shellcode search"
    _syntax_  = f"{_cmdline_} PATTERN1 PATTERN2"
    _aliases_ = ["sc-search",]

    api_base = "http://shell-storm.org"
    search_url = f"{api_base}/api/?s="

    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            err("Missing pattern to search")
            self.usage()
            return

        self.search_shellcode(argv)
        return

    def search_shellcode(self, search_options: List) -> None:
        # API : http://shell-storm.org/shellcode/
        args = "*".join(search_options)

        res = http_get(self.search_url + args)
        if res is None:
            err("Could not query search page")
            return

        ret = gef_pystring(res)

        # format: [author, OS/arch, cmd, id, link]
        lines = ret.split("\\n")
        refs = [line.split("::::") for line in lines]

        if refs:
            info("Showing matching shellcodes")
            info("\t".join(["Id", "Platform", "Description"]))
            for ref in refs:
                try:
                    _, arch, cmd, sid, _ = ref
                    gef_print("\t".join([sid, arch, cmd]))
                except ValueError:
                    continue

            info("Use `shellcode get <id>` to fetch shellcode")
        return


@register
class ShellcodeGetCommand(GenericCommand):
    """Download shellcode from shell-storm's shellcode database."""

    _cmdline_ = "shellcode get"
    _syntax_  = f"{_cmdline_} SHELLCODE_ID"
    _aliases_ = ["sc-get",]

    api_base = "http://shell-storm.org"
    get_url = f"{api_base}/shellcode/files/shellcode-{{:d}}.html"

    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) != 1:
            err("Missing ID to download")
            self.usage()
            return

        if not argv[0].isdigit():
            err("ID is not a number")
            self.usage()
            return

        self.get_shellcode(int(argv[0]))
        return

    def get_shellcode(self, sid: int) -> None:
        info(f"Downloading shellcode id={sid}")
        res = http_get(self.get_url.format(sid))
        if res is None:
            err(f"Failed to fetch shellcode #{sid}")
            return

        ok("Downloaded, written to disk...")
        with tempfile.NamedTemporaryFile(prefix="sc-", suffix=".txt", mode='w+b', delete=False, dir=gef.config["gef.tempdir"]) as fd:
            shellcode = res.split(b"<pre>")[1].split(b"</pre>")[0]
            shellcode = shellcode.replace(b"&quot;", b'"')
            fd.write(shellcode)
            ok(f"Shellcode written to '{fd.name}'")
        return


@register
class ProcessListingCommand(GenericCommand):
    """List and filter process. If a PATTERN is given as argument, results shown will be grepped
    by this pattern."""

    _cmdline_ = "process-search"
    _syntax_  = f"{_cmdline_} [-h] [--attach] [--smart-scan] [REGEX_PATTERN]"
    _aliases_ = ["ps"]
    _example_ = f"{_cmdline_} gdb.*"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self["ps_command"] = (f"{gef.session.constants['ps']} auxww", "`ps` command to get process information")
        return

    @parse_arguments({"pattern": ""}, {"--attach": True, "--smart-scan": True})
    def do_invoke(self, _: List, **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        do_attach = args.attach
        smart_scan = args.smart_scan
        pattern = args.pattern
        pattern = re.compile("^.*$") if not args else re.compile(pattern)

        for process in self.get_processes():
            pid = int(process["pid"])
            command = process["command"]

            if not re.search(pattern, command):
                continue

            if smart_scan:
                if command.startswith("[") and command.endswith("]"): continue
                if command.startswith("socat "): continue
                if command.startswith("grep "): continue
                if command.startswith("gdb "): continue

            if args and do_attach:
                ok(f"Attaching to process='{process['command']}' pid={pid:d}")
                gdb.execute(f"attach {pid:d}")
                return None

            line = [process[i] for i in ("pid", "user", "cpu", "mem", "tty", "command")]
            gef_print("\t\t".join(line))

        return None

    def get_processes(self) -> Generator[Dict[str, str], None, None]:
        output = gef_execute_external(self["ps_command"].split(), True)
        names = [x.lower().replace("%", "") for x in output[0].split()]

        for line in output[1:]:
            fields = line.split()
            t = {}

            for i, name in enumerate(names):
                if i == len(names) - 1:
                    t[name] = " ".join(fields[i:])
                else:
                    t[name] = fields[i]

            yield t

        return


@register
class ElfInfoCommand(GenericCommand):
    """Display a limited subset of ELF header information. If no argument is provided, the command will
    show information about the current ELF being debugged."""

    _cmdline_ = "elf-info"
    _syntax_  = f"{_cmdline_} [FILE]"
    _example_  = f"{_cmdline_} /bin/ls"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_arguments({}, {"--filename": ""})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]

        if is_qemu_system():
            err("Unsupported")
            return

        filename = args.filename or get_filepath()
        if filename is None:
            return

        try:
            elf = Elf(filename)
        except ValueError as ve:
            err(f"`{filename}` is an invalid value for ELF file")
            return

        data = [
            ("Magic", f"{hexdump(struct.pack('>I', elf.e_magic), show_raw=True)}"),
            ("Class", f"{elf.e_class.value:#x} - {elf.e_class.name}"),
            ("Endianness", f"{elf.e_endianness.value:#x} - {Endianness(elf.e_endianness).name}"),
            ("Version", f"{elf.e_eiversion:#x}"),
            ("OS ABI", f"{elf.e_osabi.value:#x} - {elf.e_osabi.name if elf.e_osabi else ''}"),
            ("ABI Version", f"{elf.e_abiversion:#x}"),
            ("Type", f"{elf.e_type.value:#x} - {elf.e_type.name}"),
            ("Machine", f"{elf.e_machine.value:#x} - {elf.e_machine.name}"),
            ("Program Header Table", f"{format_address(elf.e_phoff)}"),
            ("Section Header Table", f"{format_address(elf.e_shoff)}"),
            ("Header Table", f"{format_address(elf.e_phoff)}"),
            ("ELF Version", f"{elf.e_version:#x}"),
            ("Header size", "{0} ({0:#x})".format(elf.e_ehsize)),
            ("Entry point", f"{format_address(elf.e_entry)}"),
        ]

        for title, content in data:
            gef_print(f"{Color.boldify(f'{title:<22}')}: {content}")

        gef_print("")
        gef_print(titlify("Program Header"))

        gef_print("  [{:>2s}] {:12s} {:>8s} {:>10s} {:>10s} {:>8s} {:>8s} {:5s} {:>8s}".format(
            "#", "Type", "Offset", "Virtaddr", "Physaddr", "FileSiz", "MemSiz", "Flags", "Align"))

        for i, p in enumerate(elf.phdrs):
            p_type = p.p_type.name if p.p_type else ""
            p_flags = str(p.p_flags.name).lstrip("Flag.") if p.p_flags else "???"

            gef_print("  [{:2d}] {:12s} {:#8x} {:#10x} {:#10x} {:#8x} {:#8x} {:5s} {:#8x}".format(
                i, p_type, p.p_offset, p.p_vaddr, p.p_paddr, p.p_filesz, p.p_memsz, p_flags, p.p_align))

        gef_print("")
        gef_print(titlify("Section Header"))
        gef_print("  [{:>2s}] {:20s} {:>15s} {:>10s} {:>8s} {:>8s} {:>8s} {:5s} {:4s} {:4s} {:>8s}".format(
            "#", "Name", "Type", "Address", "Offset", "Size", "EntSiz", "Flags", "Link", "Info", "Align"))

        for i, s in enumerate(elf.shdrs):
            sh_type = s.sh_type.name if s.sh_type else "UNKN"
            sh_flags = str(s.sh_flags).lstrip("Flags.") if s.sh_flags else "UNKN"

            gef_print(f"  [{i:2d}] {s.name:20s} {sh_type:>15s} {s.sh_addr:#10x} {s.sh_offset:#8x} "
                      f"{s.sh_size:#8x} {s.sh_entsize:#8x} {sh_flags:5s} {s.sh_link:#4x} {s.sh_info:#4x} {s.sh_addralign:#8x}")
        return


@register
class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it. The command will test for
    well-known symbols for entry points, such as `main`, `_main`, `__libc_start_main`, etc. defined by
    the setting `entrypoint_symbols`."""

    _cmdline_ = "entry-break"
    _syntax_  = _cmdline_
    _aliases_ = ["start",]

    def __init__(self) -> None:
        super().__init__()
        self["entrypoint_symbols"] = ("main _main __libc_start_main __uClibc_main start _start", "Possible symbols for entry points")
        return

    def do_invoke(self, argv: List[str]) -> None:
        fpath = get_filepath()
        if fpath is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn(f"The file '{fpath}' is not executable.")
            return

        if is_alive() and not gef.session.qemu_mode:
            warn("gdb is already running")
            return

        bp = None
        entrypoints = self["entrypoint_symbols"].split()

        for sym in entrypoints:
            try:
                value = parse_address(sym)
                info(f"Breaking at '{value:#x}'")
                bp = EntryBreakBreakpoint(sym)
                gdb.execute(f"run {' '.join(argv)}")
                return

            except gdb.error as gdb_error:
                if 'The "remote" target does not support "run".' in str(gdb_error):
                    # this case can happen when doing remote debugging
                    gdb.execute("continue")
                    return
                continue

        # if here, clear the breakpoint if any set
        if bp:
            bp.delete()

        # break at entry point
        entry = gef.binary.entry_point

        if is_pie(fpath):
            self.set_init_tbreak_pie(entry, argv)
            gdb.execute("continue")
            return

        self.set_init_tbreak(entry)
        gdb.execute(f"run {' '.join(argv)}")
        return

    def set_init_tbreak(self, addr: int) -> EntryBreakBreakpoint:
        info(f"Breaking at entry-point: {addr:#x}")
        bp = EntryBreakBreakpoint(f"*{addr:#x}")
        return bp

    def set_init_tbreak_pie(self, addr: int, argv: List[str]) -> EntryBreakBreakpoint:
        warn("PIC binary detected, retrieving text base address")
        gdb.execute("set stop-on-solib-events 1")
        hide_context()
        gdb.execute(f"run {' '.join(argv)}")
        unhide_context()
        gdb.execute("set stop-on-solib-events 0")
        vmmap = gef.memory.maps
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        return self.set_init_tbreak(base_address + addr)


@register
class NamedBreakpointCommand(GenericCommand):
    """Sets a breakpoint and assigns a name to it, which will be shown, when it's hit."""

    _cmdline_ = "name-break"
    _syntax_  = f"{_cmdline_} name [address]"
    _aliases_ = ["nb",]
    _example  = f"{_cmdline_} main *0x4008a9"

    def __init__(self) -> None:
        super().__init__()
        return

    @parse_arguments({"name": "", "address": "*$pc"}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not args.name:
            err("Missing name for breakpoint")
            self.usage()
            return

        NamedBreakpoint(args.address, args.name)
        return


@register
class ContextCommand(GenericCommand):
    """Displays a comprehensive and modular summary of runtime context. Unless setting `enable` is
    set to False, this command will be spawned automatically every time GDB hits a breakpoint, a
    watchpoint, or any kind of interrupt. By default, it will show panes that contain the register
    states, the stack, and the disassembly code around $pc."""

    _cmdline_ = "context"
    _syntax_  = f"{_cmdline_} [legend|regs|stack|code|args|memory|source|trace|threads|extra]"
    _aliases_ = ["ctx",]

    old_registers: Dict[str, Optional[int]] = {}

    def __init__(self) -> None:
        super().__init__()
        self["enable"] = (True, "Enable/disable printing the context when breaking")
        self["show_source_code_variable_values"] = (True, "Show extra PC context info in the source code")
        self["show_stack_raw"] = (False, "Show the stack pane as raw hexdump (no dereference)")
        self["show_registers_raw"] = (False, "Show the registers pane with raw values (no dereference)")
        self["show_opcodes_size"] = (0, "Number of bytes of opcodes to display next to the disassembly")
        self["peek_calls"] = (True, "Peek into calls")
        self["peek_ret"] = (True, "Peek at return address")
        self["nb_lines_stack"] = (8, "Number of line in the stack pane")
        self["grow_stack_down"] = (False, "Order of stack downward starts at largest down to stack pointer")
        self["nb_lines_backtrace"] = (10, "Number of line in the backtrace pane")
        self["nb_lines_backtrace_before"] = (2, "Number of line in the backtrace pane before selected frame")
        self["nb_lines_threads"] = (-1, "Number of line in the threads pane")
        self["nb_lines_code"] = (6, "Number of instruction after $pc")
        self["nb_lines_code_prev"] = (3, "Number of instruction before $pc")
        self["ignore_registers"] = ("", "Space-separated list of registers not to display (e.g. '$cs $ds $gs')")
        self["clear_screen"] = (True, "Clear the screen before printing the context")
        self["layout"] = ("legend regs stack code args source memory threads trace extra", "Change the order/presence of the context sections")
        self["redirect"] = ("", "Redirect the context information to another TTY")
        self["libc_args"] = (False, "[DEPRECATED - Unused] Show libc function call args description")
        self["libc_args_path"] = ("", "[DEPRECATED - Unused] Path to libc function call args json files, provided via gef-extras")

        self.layout_mapping = {
            "legend": (self.show_legend, None, None),
            "regs": (self.context_regs, None, None),
            "stack": (self.context_stack, None, None),
            "code": (self.context_code, None, None),
            "args": (self.context_args, None, None),
            "memory": (self.context_memory, None, None),
            "source": (self.context_source, None, None),
            "trace": (self.context_trace, None, None),
            "threads": (self.context_threads, None, None),
            "extra": (self.context_additional_information, None, None),
        }

        self.instruction_iterator = gef_disassemble
        return

    def post_load(self) -> None:
        gef_on_continue_hook(self.update_registers)
        gef_on_continue_hook(self.empty_extra_messages)
        return

    def show_legend(self) -> None:
        if gef.config["gef.disable_color"] is True:
            return
        str_color = gef.config["theme.dereference_string"]
        code_addr_color = gef.config["theme.address_code"]
        stack_addr_color = gef.config["theme.address_stack"]
        heap_addr_color = gef.config["theme.address_heap"]
        changed_register_color = gef.config["theme.registers_value_changed"]

        gef_print("[ Legend: {} | {} | {} | {} | {} ]".format(Color.colorify("Modified register", changed_register_color),
                                                              Color.colorify("Code", code_addr_color),
                                                              Color.colorify("Heap", heap_addr_color),
                                                              Color.colorify("Stack", stack_addr_color),
                                                              Color.colorify("String", str_color)))
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if not self["enable"] or gef.ui.context_hidden:
            return

        if not all(_ in self.layout_mapping for _ in argv):
            self.usage()
            return

        if len(argv) > 0:
            current_layout = argv
        else:
            current_layout = self["layout"].strip().split()

        if not current_layout:
            return

        self.tty_rows, self.tty_columns = get_terminal_size()

        redirect = self["redirect"]
        if redirect and os.access(redirect, os.W_OK):
            enable_redirect_output(to_file=redirect)

        for section in current_layout:
            if section[0] == "-":
                continue

            try:
                display_pane_function, pane_title_function, condition = self.layout_mapping[section]
                if condition:
                    if not condition():
                        continue
                if pane_title_function:
                    self.context_title(pane_title_function())
                display_pane_function()
            except gdb.MemoryError as e:
                # a MemoryError will happen when $pc is corrupted (invalid address)
                err(str(e))
            except IndexError:
                # the `section` is not present, just skip
                pass

        self.context_title("")

        if self["clear_screen"] and len(argv) == 0:
            clear_screen(redirect)

        if redirect and os.access(redirect, os.W_OK):
            disable_redirect_output()
        return

    def context_title(self, m: Optional[str]) -> None:
        # allow for not displaying a title line
        if m is None:
            return

        line_color = gef.config["theme.context_title_line"]
        msg_color = gef.config["theme.context_title_message"]

        # print an empty line in case of ""
        if not m:
            gef_print(Color.colorify(HORIZONTAL_LINE * self.tty_columns, line_color))
            return

        trail_len = len(m) + 6
        title = ""
        title += Color.colorify("{:{padd}<{width}} ".format("",
                                                            width=max(self.tty_columns - trail_len, 0),
                                                            padd=HORIZONTAL_LINE),
                                line_color)
        title += Color.colorify(m, msg_color)
        title += Color.colorify(" {:{padd}<4}".format("", padd=HORIZONTAL_LINE),
                                line_color)
        gef_print(title)
        return

    def context_regs(self) -> None:
        self.context_title("registers")
        ignored_registers = set(self["ignore_registers"].split())

        # Defer to DetailRegisters by default
        if self["show_registers_raw"] is False:
            regs = [reg for reg in gef.arch.all_registers if reg not in ignored_registers]
            printable_registers = " ".join(regs)
            gdb.execute(f"registers {printable_registers}")
            return

        widest = l = max(map(len, gef.arch.all_registers))
        l += 5
        l += gef.arch.ptrsize * 2
        nb = get_terminal_size()[1] // l
        i = 1
        line = ""
        changed_color = gef.config["theme.registers_value_changed"]
        regname_color = gef.config["theme.registers_register_name"]

        for reg in gef.arch.all_registers:
            if reg in ignored_registers:
                continue

            try:
                r = gdb.parse_and_eval(reg)
                if r.type.code == gdb.TYPE_CODE_VOID:
                    continue

                new_value_type_flag = r.type.code == gdb.TYPE_CODE_FLAGS
                new_value = int(r)

            except (gdb.MemoryError, gdb.error):
                # If this exception is triggered, it means that the current register
                # is corrupted. Just use the register "raw" value (not eval-ed)
                new_value = gef.arch.register(reg)
                new_value_type_flag = False

            except Exception:
                new_value = 0
                new_value_type_flag = False

            old_value = self.old_registers.get(reg, 0)

            padreg = reg.ljust(widest, " ")
            value = align_address(new_value)
            old_value = align_address(old_value or 0)
            if value == old_value:
                line += f"{Color.colorify(padreg, regname_color)}: "
            else:
                line += f"{Color.colorify(padreg, changed_color)}: "
            if new_value_type_flag:
                line += f"{format_address_spaces(value)} "
            else:
                addr = lookup_address(align_address(int(value)))
                if addr.valid:
                    line += f"{addr!s} "
                else:
                    line += f"{format_address_spaces(value)} "

            if i % nb == 0:
                gef_print(line)
                line = ""
            i += 1

        if line:
            gef_print(line)

        gef_print(f"Flags: {gef.arch.flag_register_to_human()}")
        return

    def context_stack(self) -> None:
        self.context_title("stack")

        show_raw = self["show_stack_raw"]
        nb_lines = self["nb_lines_stack"]

        try:
            sp = gef.arch.sp
            if show_raw is True:
                mem = gef.memory.read(sp, 0x10 * nb_lines)
                gef_print(hexdump(mem, base=sp))
            else:
                gdb.execute(f"dereference -l {nb_lines:d} {sp:#x}")

        except gdb.MemoryError:
            err("Cannot read memory from $SP (corrupted stack pointer?)")

        return

    def addr_has_breakpoint(self, address: int, bp_locations: List[str]) -> bool:
        return any(hex(address) in b for b in bp_locations)

    def context_code(self) -> None:
        nb_insn = self["nb_lines_code"]
        nb_insn_prev = self["nb_lines_code_prev"]
        show_opcodes_size = "show_opcodes_size" in self and self["show_opcodes_size"]
        past_insns_color = gef.config["theme.old_context"]
        cur_insn_color = gef.config["theme.disassemble_current_instruction"]
        pc = gef.arch.pc
        breakpoints = gdb.breakpoints() or []
        bp_locations = [b.location for b in breakpoints if b.location and b.location.startswith("*")]

        frame = gdb.selected_frame()
        arch_name = f"{gef.arch.arch.lower()}:{gef.arch.mode}"

        self.context_title(f"code:{arch_name}")

        try:


            for insn in self.instruction_iterator(pc, nb_insn, nb_prev=nb_insn_prev):
                line = []
                is_taken  = False
                target    = None
                bp_prefix = Color.redify(BP_GLYPH) if self.addr_has_breakpoint(insn.address, bp_locations) else " "

                if show_opcodes_size == 0:
                    text = str(insn)
                else:
                    insn_fmt = f"{{:{show_opcodes_size}o}}"
                    text = insn_fmt.format(insn)

                if insn.address < pc:
                    line += f"{bp_prefix}  {Color.colorify(text, past_insns_color)}"

                elif insn.address == pc:
                    line += f"{bp_prefix}{Color.colorify(f'{RIGHT_ARROW[1:]}{text}', cur_insn_color)}"

                    if gef.arch.is_conditional_branch(insn):
                        is_taken, reason = gef.arch.is_branch_taken(insn)
                        if is_taken:
                            target = insn.operands[-1].split()[0]
                            reason = f"[Reason: {reason}]" if reason else ""
                            line += Color.colorify(f"\tTAKEN {reason}", "bold green")
                        else:
                            reason = f"[Reason: !({reason})]" if reason else ""
                            line += Color.colorify(f"\tNOT taken {reason}", "bold red")
                    elif gef.arch.is_call(insn) and self["peek_calls"] is True:
                        target = insn.operands[-1].split()[0]
                    elif gef.arch.is_ret(insn) and self["peek_ret"] is True:
                        target = gef.arch.get_ra(insn, frame)

                else:
                    line += f"{bp_prefix}  {text}"

                gef_print("".join(line))

                if target:
                    try:
                        address = int(target, 0) if isinstance(target, str) else target
                    except ValueError:
                        # If the operand isn't an address right now we can't parse it
                        continue
                    for i, tinsn in enumerate(self.instruction_iterator(address, nb_insn)):
                        text= f"   {DOWN_ARROW if i == 0 else ' '}  {tinsn!s}"
                        gef_print(text)
                    break

        except gdb.MemoryError:
            err("Cannot disassemble from $PC")
        return

    def context_args(self) -> None:
        insn = gef_current_instruction(gef.arch.pc)
        if not gef.arch.is_call(insn):
            return

        self.size2type = {
            1: "BYTE",
            2: "WORD",
            4: "DWORD",
            8: "QWORD",
        }

        if insn.operands[-1].startswith(self.size2type[gef.arch.ptrsize]+" PTR"):
            target = "*" + insn.operands[-1].split()[-1]
        elif "$"+insn.operands[0] in gef.arch.all_registers:
            target = f"*{gef.arch.register('$' + insn.operands[0]):#x}"
        else:
            # is there a symbol?
            ops = " ".join(insn.operands)
            if "<" in ops and ">" in ops:
                # extract it
                target = re.sub(r".*<([^\(> ]*).*", r"\1", ops)
            else:
                # it's an address, just use as is
                target = re.sub(r".*(0x[a-fA-F0-9]*).*", r"\1", ops)

        sym = gdb.lookup_global_symbol(target)
        if sym is None:
            self.print_guessed_arguments(target)
            return

        if sym.type.code != gdb.TYPE_CODE_FUNC:
            err(f"Symbol '{target}' is not a function: type={sym.type.code}")
            return

        self.print_arguments_from_symbol(target, sym)
        return

    def print_arguments_from_symbol(self, function_name: str, symbol: "gdb.Symbol") -> None:
        """If symbols were found, parse them and print the argument adequately."""
        args = []

        for i, f in enumerate(symbol.type.fields()):
            _value = gef.arch.get_ith_parameter(i, in_func=False)[1]
            _value = RIGHT_ARROW.join(dereference_from(_value))
            _name = f.name or f"var_{i}"
            _type = f.type.name or self.size2type[f.type.sizeof]
            args.append(f"{_type} {_name} = {_value}")

        self.context_title("arguments")

        if not args:
            gef_print(f"{function_name} (<void>)")
            return

        gef_print(f"{function_name} (\n   "+",\n   ".join(args)+"\n)")
        return

    def print_guessed_arguments(self, function_name: str) -> None:
        """When no symbol, read the current basic block and look for "interesting" instructions."""

        def __get_current_block_start_address() -> Optional[int]:
            pc = gef.arch.pc
            try:
                block = gdb.block_for_pc(pc)
                block_start = block.start if block else gdb_get_nth_previous_instruction_address(pc, 5)
            except RuntimeError:
                block_start = gdb_get_nth_previous_instruction_address(pc, 5)
            return block_start

        parameter_set = set()
        pc = gef.arch.pc
        block_start = __get_current_block_start_address()
        if not block_start:
            return

        function_parameters = gef.arch.function_parameters
        arg_key_color = gef.config["theme.registers_register_name"]

        for insn in self.instruction_iterator(block_start, pc - block_start):
            if not insn.operands:
                continue

            if is_x86_32():
                if insn.mnemonic == "push":
                    parameter_set.add(insn.operands[0])
            else:
                op = "$" + insn.operands[0]
                if op in function_parameters:
                    parameter_set.add(op)

                if is_x86_64():
                    # also consider extended registers
                    extended_registers = {"$rdi": ["$edi", "$di"],
                                          "$rsi": ["$esi", "$si"],
                                          "$rdx": ["$edx", "$dx"],
                                          "$rcx": ["$ecx", "$cx"],
                                         }
                    for exreg in extended_registers:
                        if op in extended_registers[exreg]:
                            parameter_set.add(exreg)

        if is_x86_32():
            nb_argument = len(parameter_set)
        else:
            nb_argument = max([function_parameters.index(p)+1 for p in parameter_set], default=0)

        args = []
        for i in range(nb_argument):
            _key, _values = gef.arch.get_ith_parameter(i, in_func=False)
            _values = RIGHT_ARROW.join(dereference_from(_values))
            args.append(f"{Color.colorify(_key, arg_key_color)} = {_values}")

        self.context_title("arguments (guessed)")
        gef_print(f"{function_name} (")
        if args:
            gef_print("   " + ",\n   ".join(args))
        gef_print(")")
        return

    def line_has_breakpoint(self, file_name: str, line_number: int, bp_locations: List[str]) -> bool:
        filename_line = f"{file_name}:{line_number}"
        return any(filename_line in loc for loc in bp_locations)

    def context_source(self) -> None:
        try:
            pc = gef.arch.pc
            symtabline = gdb.find_pc_line(pc)
            symtab = symtabline.symtab
            # we subtract one because the line number returned by gdb start at 1
            line_num = symtabline.line - 1
            if not symtab.is_valid():
                return

            fpath = symtab.fullname()
            with open(fpath, "r") as f:
                lines = [l.rstrip() for l in f.readlines()]

        except Exception:
            return

        file_base_name = os.path.basename(symtab.filename)
        breakpoints = gdb.breakpoints() or []
        bp_locations = [b.location for b in breakpoints if b.location and file_base_name in b.location]
        past_lines_color = gef.config["theme.old_context"]

        nb_line = self["nb_lines_code"]
        fn = symtab.filename
        if len(fn) > 20:
            fn = f"{fn[:15]}[...]{os.path.splitext(fn)[1]}"
        title = f"source:{fn}+{line_num + 1}"
        cur_line_color = gef.config["theme.source_current_line"]
        self.context_title(title)
        show_extra_info = self["show_source_code_variable_values"]

        for i in range(line_num - nb_line + 1, line_num + nb_line):
            if i < 0:
                continue

            bp_prefix = Color.redify(BP_GLYPH) if self.line_has_breakpoint(file_base_name, i + 1, bp_locations) else " "

            if i < line_num:
                gef_print("{}{}".format(bp_prefix, Color.colorify(f"  {i + 1:4d}\t {lines[i]}", past_lines_color)))

            if i == line_num:
                prefix = f"{bp_prefix}{RIGHT_ARROW[1:]}{i + 1:4d}\t "
                leading = len(lines[i]) - len(lines[i].lstrip())
                if show_extra_info:
                    extra_info = self.get_pc_context_info(pc, lines[i])
                    if extra_info:
                        gef_print(f"{' ' * (len(prefix) + leading)}{extra_info}")
                gef_print(Color.colorify(f"{prefix}{lines[i]}", cur_line_color))

            if i > line_num:
                try:
                    gef_print(f"{bp_prefix}  {i + 1:4d}\t {lines[i]}")
                except IndexError:
                    break
        return

    def get_pc_context_info(self, pc: int, line: str) -> str:
        try:
            current_block = gdb.block_for_pc(pc)
            if not current_block or not current_block.is_valid(): return ""
            m = collections.OrderedDict()
            while current_block and not current_block.is_static:
                for sym in current_block:
                    symbol = sym.name
                    if not sym.is_function and re.search(fr"\W{symbol}\W", line):
                        val = gdb.parse_and_eval(symbol)
                        if val.type.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                            addr = int(val.address)
                            addrs = dereference_from(addr)
                            if len(addrs) > 2:
                                addrs = [addrs[0], "[...]", addrs[-1]]

                            f = f" {RIGHT_ARROW} "
                            val = f.join(addrs)
                        elif val.type.code == gdb.TYPE_CODE_INT:
                            val = hex(int(val))
                        else:
                            continue

                        if symbol not in m:
                            m[symbol] = val
                current_block = current_block.superblock

            if m:
                return "// " + ", ".join([f"{Color.yellowify(a)}={b}" for a, b in m.items()])
        except Exception:
            pass
        return ""

    def context_trace(self) -> None:
        self.context_title("trace")

        nb_backtrace = self["nb_lines_backtrace"]
        if nb_backtrace <= 0:
            return

        # backward compat for gdb (gdb < 7.10)
        if not hasattr(gdb, "FrameDecorator"):
            gdb.execute(f"backtrace {nb_backtrace:d}")
            return

        orig_frame = gdb.selected_frame()
        current_frame = gdb.newest_frame()
        frames = [current_frame]
        while current_frame != orig_frame:
            current_frame = current_frame.older()
            frames.append(current_frame)

        nb_backtrace_before = self["nb_lines_backtrace_before"]
        level = max(len(frames) - nb_backtrace_before - 1, 0)
        current_frame = frames[level]

        while current_frame:
            current_frame.select()
            if not current_frame.is_valid():
                continue

            pc = current_frame.pc()
            name = current_frame.name()
            items = []
            items.append(f"{pc:#x}")
            if name:
                frame_args = gdb.FrameDecorator.FrameDecorator(current_frame).frame_args() or []
                m = "{}({})".format(Color.greenify(name),
                                    ", ".join(["{}={!s}".format(Color.yellowify(x.sym),
                                                                x.sym.value(current_frame)) for x in frame_args]))
                items.append(m)
            else:
                try:
                    insn = next(gef_disassemble(pc, 1))
                except gdb.MemoryError:
                    break

                # check if the gdb symbol table may know the address
                sym_found = gdb_get_location_from_symbol(pc)
                symbol = ""
                if sym_found:
                    sym_name, offset = sym_found
                    symbol = f" <{sym_name}+{offset:x}> "

                items.append(Color.redify(f"{symbol}{insn.mnemonic} {', '.join(insn.operands)}"))

            gef_print("[{}] {}".format(Color.colorify(f"#{level}", "bold green" if current_frame == orig_frame else "bold pink"),
                                       RIGHT_ARROW.join(items)))
            current_frame = current_frame.older()
            level += 1
            nb_backtrace -= 1
            if nb_backtrace == 0:
                break

        orig_frame.select()
        return

    def context_threads(self) -> None:
        def reason() -> str:
            res = gdb.execute("info program", to_string=True)
            if not res:
                return "NOT RUNNING"

            for line in res.splitlines():
                line = line.strip()
                if line.startswith("It stopped with signal "):
                    return line.replace("It stopped with signal ", "").split(",", 1)[0]
                if line == "The program being debugged is not being run.":
                    return "NOT RUNNING"
                if line == "It stopped at a breakpoint that has since been deleted.":
                    return "TEMPORARY BREAKPOINT"
                if line.startswith("It stopped at breakpoint "):
                    return "BREAKPOINT"
                if line == "It stopped after being stepped.":
                    return "SINGLE STEP"

            return "STOPPED"

        self.context_title("threads")

        threads = gdb.selected_inferior().threads()[::-1]
        idx = self["nb_lines_threads"]
        if idx > 0:
            threads = threads[0:idx]

        if idx == 0:
            return

        if not threads:
            err("No thread selected")
            return

        selected_thread = gdb.selected_thread()
        selected_frame = gdb.selected_frame()

        for i, thread in enumerate(threads):
            line = f"[{Color.colorify(f'#{i:d}', 'bold green' if thread == selected_thread else 'bold pink')}] Id {thread.num:d}, "
            if thread.name:
                line += f"""Name: "{thread.name}", """
            if thread.is_running():
                line += Color.colorify("running", "bold green")
            elif thread.is_stopped():
                line += Color.colorify("stopped", "bold red")
                thread.switch()
                frame = gdb.selected_frame()
                frame_name = frame.name()

                # check if the gdb symbol table may know the address
                if not frame_name:
                    sym_found = gdb_get_location_from_symbol(frame.pc())
                    if sym_found:
                        sym_name, offset = sym_found
                        frame_name = f"<{sym_name}+{offset:x}>"

                line += (f" {Color.colorify(f'{frame.pc():#x}', 'blue')} in "
                         f"{Color.colorify(frame_name or '??', 'bold yellow')} (), "
                         f"reason: {Color.colorify(reason(), 'bold pink')}")
            elif thread.is_exited():
                line += Color.colorify("exited", "bold yellow")
            gef_print(line)
            i += 1

        selected_thread.switch()
        selected_frame.select()
        return

    def context_additional_information(self) -> None:
        if not gef.ui.context_messages:
            return

        self.context_title("extra")
        for level, text in gef.ui.context_messages:
            if level == "error": err(text)
            elif level == "warn": warn(text)
            elif level == "success": ok(text)
            else: info(text)
        return

    def context_memory(self) -> None:
        for address, opt in sorted(gef.ui.watches.items()):
            sz, fmt = opt[0:2]
            self.context_title(f"memory:{address:#x}")
            if fmt == "pointers":
                gdb.execute(f"dereference -l {sz:d} {address:#x}")
            else:
                gdb.execute(f"hexdump {fmt} -s {sz:d} {address:#x}")

    @classmethod
    def update_registers(cls, _) -> None:
        for reg in gef.arch.all_registers:
            try:
                cls.old_registers[reg] = gef.arch.register(reg)
            except Exception:
                cls.old_registers[reg] = 0
        return

    def empty_extra_messages(self, _) -> None:
        gef.ui.context_messages.clear()
        return


@register
class MemoryCommand(GenericCommand):
    """Add or remove address ranges to the memory view."""
    _cmdline_ = "memory"
    _syntax_  = f"{_cmdline_} (watch|unwatch|reset|list)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        self.usage()
        return


@register
class MemoryWatchCommand(GenericCommand):
    """Adds address ranges to the memory view."""
    _cmdline_ = "memory watch"
    _syntax_  = f"{_cmdline_} ADDRESS [SIZE] [(qword|dword|word|byte|pointers)]"
    _example_ = (f"\n{_cmdline_} 0x603000 0x100 byte"
                 f"\n{_cmdline_} $sp")

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) not in (1, 2, 3):
            self.usage()
            return

        address = parse_address(argv[0])
        size    = parse_address(argv[1]) if len(argv) > 1 else 0x10
        group   = "byte"

        if len(argv) == 3:
            group = argv[2].lower()
            if group not in ("qword", "dword", "word", "byte", "pointers"):
                warn(f"Unexpected grouping '{group}'")
                self.usage()
                return
        else:
            if gef.arch.ptrsize == 4:
                group = "dword"
            elif gef.arch.ptrsize == 8:
                group = "qword"

        gef.ui.watches[address] = (size, group)
        ok(f"Adding memwatch to {address:#x}")
        return


@register
class MemoryUnwatchCommand(GenericCommand):
    """Removes address ranges to the memory view."""
    _cmdline_ = "memory unwatch"
    _syntax_  = f"{_cmdline_} ADDRESS"
    _example_ = (f"\n{_cmdline_} 0x603000"
                 f"\n{_cmdline_} $sp")

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            self.usage()
            return

        address = parse_address(argv[0])
        res = gef.ui.watches.pop(address, None)
        if not res:
            warn(f"You weren't watching {address:#x}")
        else:
            ok(f"Removed memwatch of {address:#x}")
        return


@register
class MemoryWatchResetCommand(GenericCommand):
    """Removes all watchpoints."""
    _cmdline_ = "memory reset"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        gef.ui.watches.clear()
        ok("Memory watches cleared")
        return


@register
class MemoryWatchListCommand(GenericCommand):
    """Lists all watchpoints to display in context layout."""
    _cmdline_ = "memory list"
    _syntax_  = f"{_cmdline_}"

    @only_if_gdb_running
    def do_invoke(self, _: List[str]) -> None:
        if not gef.ui.watches:
            info("No memory watches")
            return

        info("Memory watches:")
        for address, opt in sorted(gef.ui.watches.items()):
            gef_print(f"- {address:#x} ({opt[0]}, {opt[1]})")
        return


@register
class HexdumpCommand(GenericCommand):
    """Display SIZE lines of hexdump from the memory location pointed by LOCATION."""

    _cmdline_ = "hexdump"
    _syntax_  = f"{_cmdline_} (qword|dword|word|byte) [LOCATION] [--size SIZE] [--reverse]"
    _example_ = f"{_cmdline_} byte $rsp --size 16 --reverse"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION, prefix=True)
        self["always_show_ascii"] = (False, "If true, hexdump will always display the ASCII dump")
        self.format: Optional[str] = None
        self.__last_target = "$sp"
        return

    @only_if_gdb_running
    @parse_arguments({"address": "",}, {("--reverse", "-r"): True, ("--size", "-s"): 0})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        valid_formats = ["byte", "word", "dword", "qword"]
        if not self.format or self.format not in valid_formats:
            err("Invalid command")
            return

        args : argparse.Namespace = kwargs["arguments"]
        target = args.address or self.__last_target
        start_addr = parse_address(target)
        read_from = align_address(start_addr)

        if self.format == "byte":
            read_len = args.size or 0x40
            read_from += self.repeat_count * read_len
            mem = gef.memory.read(read_from, read_len)
            lines = hexdump(mem, base=read_from).splitlines()
        else:
            read_len = args.size or 0x10
            lines = self._hexdump(read_from, read_len, self.format, self.repeat_count * read_len)

        if args.reverse:
            lines.reverse()

        self.__last_target = target
        gef_print("\n".join(lines))
        return

    def _hexdump(self, start_addr: int, length: int, arrange_as: str, offset: int = 0) -> List[str]:
        endianness = gef.arch.endianness

        base_address_color = gef.config["theme.dereference_base_address"]
        show_ascii = gef.config["hexdump.always_show_ascii"]

        formats = {
            "qword": ("Q", 8),
            "dword": ("I", 4),
            "word": ("H", 2),
        }

        r, l = formats[arrange_as]
        fmt_str = f"{{base}}{VERTICAL_LINE}+{{offset:#06x}}   {{sym}}{{val:#0{l*2+2}x}}   {{text}}"
        fmt_pack = f"{endianness!s}{r}"
        lines = []

        i = 0
        text = ""
        while i < length:
            cur_addr = start_addr + (i + offset) * l
            sym = gdb_get_location_from_symbol(cur_addr)
            sym = "<{:s}+{:04x}> ".format(*sym) if sym else ""
            mem = gef.memory.read(cur_addr, l)
            val = struct.unpack(fmt_pack, mem)[0]
            if show_ascii:
                text = "".join([chr(b) if 0x20 <= b < 0x7F else "." for b in mem])
            lines.append(fmt_str.format(base=Color.colorify(format_address(cur_addr), base_address_color),
                                        offset=(i + offset) * l, sym=sym, val=val, text=text))
            i += 1

        return lines


@register
class HexdumpQwordCommand(HexdumpCommand):
    """Display SIZE lines of hexdump as QWORD from the memory location pointed by ADDRESS."""

    _cmdline_ = "hexdump qword"
    _syntax_  = f"{_cmdline_} [ADDRESS] [[L][SIZE]] [REVERSE]"
    _example_ = f"{_cmdline_} qword $rsp L16 REVERSE"

    def __init__(self) -> None:
        super().__init__()
        self.format = "qword"
        return


@register
class HexdumpDwordCommand(HexdumpCommand):
    """Display SIZE lines of hexdump as DWORD from the memory location pointed by ADDRESS."""

    _cmdline_ = "hexdump dword"
    _syntax_  = f"{_cmdline_} [ADDRESS] [[L][SIZE]] [REVERSE]"
    _example_ = f"{_cmdline_} $esp L16 REVERSE"

    def __init__(self) -> None:
        super().__init__()
        self.format = "dword"
        return


@register
class HexdumpWordCommand(HexdumpCommand):
    """Display SIZE lines of hexdump as WORD from the memory location pointed by ADDRESS."""

    _cmdline_ = "hexdump word"
    _syntax_  = f"{_cmdline_} [ADDRESS] [[L][SIZE]] [REVERSE]"
    _example_ = f"{_cmdline_} $esp L16 REVERSE"

    def __init__(self) -> None:
        super().__init__()
        self.format = "word"
        return


@register
class HexdumpByteCommand(HexdumpCommand):
    """Display SIZE lines of hexdump as BYTE from the memory location pointed by ADDRESS."""

    _cmdline_ = "hexdump byte"
    _syntax_  = f"{_cmdline_} [ADDRESS] [[L][SIZE]] [REVERSE]"
    _example_ = f"{_cmdline_} $rsp L16"

    def __init__(self) -> None:
        super().__init__()
        self.format = "byte"
        return


@register
class PatchCommand(GenericCommand):
    """Write specified values to the specified address."""

    _cmdline_ = "patch"
    _syntax_  = (f"{_cmdline_} (qword|dword|word|byte) LOCATION VALUES\n"
                 f"{_cmdline_} string LOCATION \"double-escaped string\"")
    SUPPORTED_SIZES = {
        "qword": (8, "Q"),
        "dword": (4, "L"),
        "word": (2, "H"),
        "byte": (1, "B"),
    }

    def __init__(self) -> None:
        super().__init__(prefix=True, complete=gdb.COMPLETE_LOCATION)
        self.format: Optional[str] = None
        return

    @only_if_gdb_running
    @parse_arguments({"location": "", "values": ["", ]}, {})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        if not self.format or self.format not in self.SUPPORTED_SIZES:
            self.usage()
            return

        if not args.location or not args.values:
            self.usage()
            return

        addr = align_address(parse_address(args.location))
        size, fcode = self.SUPPORTED_SIZES[self.format]
        values = args.values

        if size == 1:
            if values[0].startswith("$_gef"):
                var_name = values[0]
                try:
                    values = str(gdb.parse_and_eval(var_name)).lstrip("{").rstrip("}").replace(",","").split(" ")
                except:
                    gef_print(f"Bad variable specified, check value with command: p {var_name}")
                    return

        d = str(gef.arch.endianness)
        for value in values:
            value = parse_address(value) & ((1 << size * 8) - 1)
            vstr = struct.pack(d + fcode, value)
            gef.memory.write(addr, vstr, length=size)
            addr += size
        return


@register
class PatchQwordCommand(PatchCommand):
    """Write specified QWORD to the specified address."""

    _cmdline_ = "patch qword"
    _syntax_  = f"{_cmdline_} LOCATION QWORD1 [QWORD2 [QWORD3..]]"
    _example_ = f"{_cmdline_} $rip 0x4141414141414141"

    def __init__(self) -> None:
        super().__init__()
        self.format = "qword"
        return


@register
class PatchDwordCommand(PatchCommand):
    """Write specified DWORD to the specified address."""

    _cmdline_ = "patch dword"
    _syntax_  = f"{_cmdline_} LOCATION DWORD1 [DWORD2 [DWORD3..]]"
    _example_ = f"{_cmdline_} $rip 0x41414141"

    def __init__(self) -> None:
        super().__init__()
        self.format = "dword"
        return


@register
class PatchWordCommand(PatchCommand):
    """Write specified WORD to the specified address."""

    _cmdline_ = "patch word"
    _syntax_  = f"{_cmdline_} LOCATION WORD1 [WORD2 [WORD3..]]"
    _example_ = f"{_cmdline_} $rip 0x4141"

    def __init__(self) -> None:
        super().__init__()
        self.format = "word"
        return


@register
class PatchByteCommand(PatchCommand):
    """Write specified BYTE to the specified address."""

    _cmdline_ = "patch byte"
    _syntax_  = f"{_cmdline_} LOCATION BYTE1 [BYTE2 [BYTE3..]]"
    _example_ = f"{_cmdline_} $pc 0x41 0x41 0x41 0x41 0x41"

    def __init__(self) -> None:
        super().__init__()
        self.format = "byte"
        return


@register
class PatchStringCommand(GenericCommand):
    """Write specified string to the specified memory location pointed by ADDRESS."""

    _cmdline_ = "patch string"
    _syntax_  = f"{_cmdline_} ADDRESS \"double backslash-escaped string\""
    _example_ = f"{_cmdline_} $sp \"GEFROCKS\""

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        argc = len(argv)
        if argc != 2:
            self.usage()
            return

        location, s = argv[0:2]
        addr = align_address(parse_address(location))

        try:
            s = codecs.escape_decode(s)[0]
        except binascii.Error:
            gef_print(f"Could not decode '\\xXX' encoded string \"{s}\"")
            return

        gef.memory.write(addr, s, len(s))
        return


@lru_cache()
def dereference_from(address: int) -> List[str]:
    if not is_alive():
        return [format_address(address),]

    code_color = gef.config["theme.dereference_code"]
    string_color = gef.config["theme.dereference_string"]
    max_recursion = gef.config["dereference.max_recursion"] or 10
    addr = lookup_address(align_address(address))
    msg = [format_address(addr.value),]
    seen_addrs = set()

    while addr.section and max_recursion:
        if addr.value in seen_addrs:
            msg.append("[loop detected]")
            break
        seen_addrs.add(addr.value)

        max_recursion -= 1

        # Is this value a pointer or a value?
        # -- If it's a pointer, dereference
        deref = addr.dereference()
        if deref is None:
            # if here, dereferencing addr has triggered a MemoryError, no need to go further
            msg.append(str(addr))
            break

        new_addr = lookup_address(deref)
        if new_addr.valid:
            addr = new_addr
            msg.append(str(addr))
            continue

        # -- Otherwise try to parse the value
        if addr.section:
            if addr.section.is_executable() and addr.is_in_text_segment() and not is_ascii_string(addr.value):
                insn = gef_current_instruction(addr.value)
                insn_str = f"{insn.location} {insn.mnemonic} {', '.join(insn.operands)}"
                msg.append(Color.colorify(insn_str, code_color))
                break

            elif addr.section.permission & Permission.READ:
                if is_ascii_string(addr.value):
                    s = gef.memory.read_cstring(addr.value)
                    if len(s) < gef.arch.ptrsize:
                        txt = f'{format_address(deref)} ("{Color.colorify(s, string_color)}"?)'
                    elif len(s) > 50:
                        txt = Color.colorify(f'"{s[:50]}[...]"', string_color)
                    else:
                        txt = Color.colorify(f'"{s}"', string_color)

                    msg.append(txt)
                    break

        # if not able to parse cleanly, simply display and break
        val = "{:#0{ma}x}".format(int(deref & 0xFFFFFFFFFFFFFFFF), ma=(gef.arch.ptrsize * 2 + 2))
        msg.append(val)
        break

    return msg


@register
class DereferenceCommand(GenericCommand):
    """Dereference recursively from an address and display information. This acts like WinDBG `dps`
    command."""

    _cmdline_ = "dereference"
    _syntax_  = f"{_cmdline_} [-h] [--length LENGTH] [--reference REFERENCE] [address]"
    _aliases_ = ["telescope", ]
    _example_ = f"{_cmdline_} --length 20 --reference $sp+0x10 $sp"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self["max_recursion"] = (7, "Maximum level of pointer recursion")
        return

    @staticmethod
    def pprint_dereferenced(addr: int, idx: int, base_offset: int = 0) -> str:
        base_address_color = gef.config["theme.dereference_base_address"]
        registers_color = gef.config["theme.dereference_register_value"]

        sep = f" {RIGHT_ARROW} "
        memalign = gef.arch.ptrsize

        offset = idx * memalign
        current_address = align_address(addr + offset)
        addrs = dereference_from(current_address)
        l = ""
        addr_l = format_address(int(addrs[0], 16))
        l += "{}{}{:+#07x}: {:{ma}s}".format(Color.colorify(addr_l, base_address_color),
                                             VERTICAL_LINE, base_offset+offset,
                                             sep.join(addrs[1:]), ma=(memalign*2 + 2))

        register_hints = []

        for regname in gef.arch.all_registers:
            regvalue = gef.arch.register(regname)
            if current_address == regvalue:
                register_hints.append(regname)

        if register_hints:
            m = f"\t{LEFT_ARROW}{', '.join(list(register_hints))}"
            l += Color.colorify(m, registers_color)

        offset += memalign
        return l

    @only_if_gdb_running
    @parse_arguments({"address": "$sp"}, {("-r", "--reference"): "", ("-l", "--length"): 10})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        nb = args.length

        target = args.address
        target_addr = parse_address(target)

        reference = args.reference or target
        ref_addr = parse_address(reference)

        if process_lookup_address(target_addr) is None:
            err(f"Unmapped address: '{target}'")
            return

        if process_lookup_address(ref_addr) is None:
            err(f"Unmapped address: '{reference}'")
            return

        if gef.config["context.grow_stack_down"] is True:
            insnum_step = -1
            if nb > 0:
                from_insnum = nb * (self.repeat_count + 1) - 1
                to_insnum = self.repeat_count * nb - 1
            else:
                from_insnum = self.repeat_count * nb
                to_insnum = nb * (self.repeat_count + 1)
        else:
            insnum_step = 1
            if nb > 0:
                from_insnum = self.repeat_count * nb
                to_insnum = nb * (self.repeat_count + 1)
            else:
                from_insnum = nb * (self.repeat_count + 1) + 1
                to_insnum = (self.repeat_count * nb) + 1

        start_address = align_address(target_addr)
        base_offset = start_address - align_address(ref_addr)

        for i in range(from_insnum, to_insnum, insnum_step):
            gef_print(DereferenceCommand.pprint_dereferenced(start_address, i, base_offset))

        return


@register
class ASLRCommand(GenericCommand):
    """View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not
    attached). This command allows to change that setting."""

    _cmdline_ = "aslr"
    _syntax_  = f"{_cmdline_} [(on|off)]"

    def do_invoke(self, argv: List[str]) -> None:
        argc = len(argv)

        if argc == 0:
            ret = gdb.execute("show disable-randomization", to_string=True) or ""
            i = ret.find("virtual address space is ")
            if i < 0:
                return

            msg = "ASLR is currently "
            if ret[i + 25:].strip() == "on.":
                msg += Color.redify("disabled")
            else:
                msg += Color.greenify("enabled")

            gef_print(msg)
            return

        elif argc == 1:
            if argv[0] == "on":
                info("Enabling ASLR")
                gdb.execute("set disable-randomization off")
                return
            elif argv[0] == "off":
                info("Disabling ASLR")
                gdb.execute("set disable-randomization on")
                return

            warn("Invalid command")

        self.usage()
        return


@register
class ResetCacheCommand(GenericCommand):
    """Reset cache of all stored data. This command is here for debugging and test purposes, GEF
    handles properly the cache reset under "normal" scenario."""

    _cmdline_ = "reset-cache"
    _syntax_  = _cmdline_

    def do_invoke(self, _: List[str]) -> None:
        reset_all_caches()
        return


@register
class VMMapCommand(GenericCommand):
    """Display a comprehensive layout of the virtual memory mapping. If a filter argument, GEF will
    filter out the mapping whose pathname do not match that filter."""

    _cmdline_ = "vmmap"
    _syntax_  = f"{_cmdline_} [FILTER]"
    _example_ = f"{_cmdline_} libc"

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        vmmap = gef.memory.maps
        if not vmmap:
            err("No address mapping information found")
            return

        if not gef.config["gef.disable_color"]:
            self.show_legend()

        color = gef.config["theme.table_heading"]

        headers = ["Start", "End", "Offset", "Perm", "Path"]
        gef_print(Color.colorify("{:<{w}s}{:<{w}s}{:<{w}s}{:<4s} {:s}".format(*headers, w=gef.arch.ptrsize*2+3), color))

        for entry in vmmap:
            if not argv:
                self.print_entry(entry)
                continue
            if argv[0] in entry.path:
                self.print_entry(entry)
            elif self.is_integer(argv[0]):
                addr = int(argv[0], 0)
                if addr >= entry.page_start and addr < entry.page_end:
                    self.print_entry(entry)
        return

    def print_entry(self, entry: Section) -> None:
        line_color = ""
        if entry.path == "[stack]":
            line_color = gef.config["theme.address_stack"]
        elif entry.path == "[heap]":
            line_color = gef.config["theme.address_heap"]
        elif entry.permission & Permission.READ and entry.permission & Permission.EXECUTE:
            line_color = gef.config["theme.address_code"]

        l = [
            Color.colorify(format_address(entry.page_start), line_color),
            Color.colorify(format_address(entry.page_end), line_color),
            Color.colorify(format_address(entry.offset), line_color),
        ]
        if entry.permission == Permission.ALL:
            l.append(Color.colorify(str(entry.permission), "underline " + line_color))
        else:
            l.append(Color.colorify(str(entry.permission), line_color))

        l.append(Color.colorify(entry.path, line_color))
        line = " ".join(l)

        gef_print(line)
        return

    def show_legend(self) -> None:
        code_addr_color = gef.config["theme.address_code"]
        stack_addr_color = gef.config["theme.address_stack"]
        heap_addr_color = gef.config["theme.address_heap"]

        gef_print("[ Legend:  {} | {} | {} ]".format(Color.colorify("Code", code_addr_color),
                                                     Color.colorify("Heap", heap_addr_color),
                                                     Color.colorify("Stack", stack_addr_color)
        ))
        return

    def is_integer(self, n: str) -> bool:
        try:
            int(n, 0)
        except ValueError:
            return False
        return True


@register
class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary. This command extends the GDB command
    `info files`, by retrieving more information from extra sources, and providing a better
    display. If an argument FILE is given, the output will grep information related to only that file.
    If an argument name is also given, the output will grep to the name within FILE."""

    _cmdline_ = "xfiles"
    _syntax_  = f"{_cmdline_} [FILE [NAME]]"
    _example_ = f"\n{_cmdline_} libc\n{_cmdline_} libc IO_vtables"

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        color = gef.config["theme.table_heading"]
        headers = ["Start", "End", "Name", "File"]
        gef_print(Color.colorify("{:<{w}s}{:<{w}s}{:<21s} {:s}".format(*headers, w=gef.arch.ptrsize*2+3), color))

        filter_by_file = argv[0] if argv and argv[0] else None
        filter_by_name = argv[1] if len(argv) > 1 and argv[1] else None

        for xfile in get_info_files():
            if filter_by_file:
                if filter_by_file not in xfile.filename:
                    continue
                if filter_by_name and filter_by_name not in xfile.name:
                    continue

            l = [
                format_address(xfile.zone_start),
                format_address(xfile.zone_end),
                f"{xfile.name:<21s}",
                xfile.filename,
            ]
            gef_print(" ".join(l))
        return


@register
class XAddressInfoCommand(GenericCommand):
    """Retrieve and display runtime information for the location(s) given as parameter."""

    _cmdline_ = "xinfo"
    _syntax_  = f"{_cmdline_} LOCATION"
    _example_ = f"{_cmdline_} $pc"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            err("At least one valid address must be specified")
            self.usage()
            return

        for sym in argv:
            try:
                addr = align_address(parse_address(sym))
                gef_print(titlify(f"xinfo: {addr:#x}"))
                self.infos(addr)

            except gdb.error as gdb_err:
                err(f"{gdb_err}")
        return

    def infos(self, address: int) -> None:
        addr = lookup_address(address)
        if not addr.valid:
            warn(f"Cannot reach {address:#x} in memory space")
            return

        sect = addr.section
        info = addr.info

        if sect:
            gef_print(f"Page: {format_address(sect.page_start)} {RIGHT_ARROW} "
                      f"{format_address(sect.page_end)} (size={sect.page_end-sect.page_start:#x})"
                      f"\nPermissions: {sect.permission}"
                      f"\nPathname: {sect.path}"
                      f"\nOffset (from page): {addr.value-sect.page_start:#x}"
                      f"\nInode: {sect.inode}")

        if info:
            gef_print(f"Segment: {info.name} "
                      f"({format_address(info.zone_start)}-{format_address(info.zone_end)})"
                      f"\nOffset (from segment): {addr.value-info.zone_start:#x}")

        sym = gdb_get_location_from_symbol(address)
        if sym:
            name, offset = sym
            msg = f"Symbol: {name}"
            if offset:
                msg += f"+{offset:d}"
            gef_print(msg)

        return


@register
class XorMemoryCommand(GenericCommand):
    """XOR a block of memory. The command allows to simply display the result, or patch it
    runtime at runtime."""

    _cmdline_ = "xor-memory"
    _syntax_  = f"{_cmdline_} (display|patch) ADDRESS SIZE KEY"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    def do_invoke(self, _: List[str]) -> None:
        self.usage()
        return


@register
class XorMemoryDisplayCommand(GenericCommand):
    """Display a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be
    provided in hexadecimal format."""

    _cmdline_ = "xor-memory display"
    _syntax_  = f"{_cmdline_} ADDRESS SIZE KEY"
    _example_ = f"{_cmdline_} $sp 16 41414141"

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) != 3:
            self.usage()
            return

        address = parse_address(argv[0])
        length = int(argv[1], 0)
        key = argv[2]
        block = gef.memory.read(address, length)
        info(f"Displaying XOR-ing {address:#x}-{address + len(block):#x} with {key!r}")

        gef_print(titlify("Original block"))
        gef_print(hexdump(block, base=address))

        gef_print(titlify("XOR-ed block"))
        gef_print(hexdump(xor(block, key), base=address))
        return


@register
class XorMemoryPatchCommand(GenericCommand):
    """Patch a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be
    provided in hexadecimal format."""

    _cmdline_ = "xor-memory patch"
    _syntax_  = f"{_cmdline_} ADDRESS SIZE KEY"
    _example_ = f"{_cmdline_} $sp 16 41414141"

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) != 3:
            self.usage()
            return

        address = parse_address(argv[0])
        length = int(argv[1], 0)
        key = argv[2]
        block = gef.memory.read(address, length)
        info(f"Patching XOR-ing {address:#x}-{address + len(block):#x} with {key!r}")
        xored_block = xor(block, key)
        gef.memory.write(address, xored_block, length)
        return


@register
class TraceRunCommand(GenericCommand):
    """Create a runtime trace of all instructions executed from $pc to LOCATION specified. The
    trace is stored in a text file that can be next imported in IDA Pro to visualize the runtime
    path."""

    _cmdline_ = "trace-run"
    _syntax_  = f"{_cmdline_} LOCATION [MAX_CALL_DEPTH]"
    _example_ = f"{_cmdline_} 0x555555554610"

    def __init__(self) -> None:
        super().__init__(self._cmdline_, complete=gdb.COMPLETE_LOCATION)
        self["max_tracing_recursion"] = (1, "Maximum depth of tracing")
        self["tracefile_prefix"] = ("./gef-trace-", "Specify the tracing output file prefix")
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) not in (1, 2):
            self.usage()
            return

        if len(argv) == 2 and argv[1].isdigit():
            depth = int(argv[1])
        else:
            depth = 1

        try:
            loc_start   = gef.arch.pc
            loc_end     = parse_address(argv[0])
        except gdb.error as e:
            err(f"Invalid location: {e}")
            return

        self.trace(loc_start, loc_end, depth)
        return

    def get_frames_size(self) -> int:
        n = 0
        f = gdb.newest_frame()
        while f:
            n += 1
            f = f.older()
        return n

    def trace(self, loc_start: int, loc_end: int, depth: int) -> None:
        info(f"Tracing from {loc_start:#x} to {loc_end:#x} (max depth={depth:d})")
        logfile = f"{self['tracefile_prefix']}{loc_start:#x}-{loc_end:#x}.txt"
        with RedirectOutputContext(to_file=logfile):
            hide_context()
            self.start_tracing(loc_start, loc_end, depth)
            unhide_context()
        ok(f"Done, logfile stored as '{logfile}'")
        info("Hint: import logfile with `ida_color_gdb_trace.py` script in IDA to visualize path")
        return

    def start_tracing(self, loc_start: int, loc_end: int, depth: int) -> None:
        loc_cur = loc_start
        frame_count_init = self.get_frames_size()

        gef_print("#",
                  f"# Execution tracing of {get_filepath()}",
                  f"# Start address: {format_address(loc_start)}",
                  f"# End address: {format_address(loc_end)}",
                  f"# Recursion level: {depth:d}",
                  "# automatically generated by gef.py",
                  "#\n", sep="\n")

        while loc_cur != loc_end:
            try:
                delta = self.get_frames_size() - frame_count_init

                if delta <= depth:
                    gdb.execute("stepi")
                else:
                    gdb.execute("finish")

                loc_cur = gef.arch.pc
                gdb.flush()

            except gdb.error as e:
                gef_print("#",
                          f"# Execution interrupted at address {format_address(loc_cur)}",
                          f"# Exception: {e}",
                          "#\n", sep="\n")
                break

        return


@register
class PatternCommand(GenericCommand):
    """Generate or Search a De Bruijn Sequence of unique substrings of length N
    and a total length of LENGTH. The default value of N is set to match the
    currently loaded architecture."""

    _cmdline_ = "pattern"
    _syntax_  = f"{_cmdline_} (create|search) ARGS"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        self["length"] = (1024, "Default length of a cyclic buffer to generate")
        return

    def do_invoke(self, _: List[str]) -> None:
        self.usage()
        return


@register
class PatternCreateCommand(GenericCommand):
    """Generate a De Bruijn Sequence of unique substrings of length N and a
    total length of LENGTH. The default value of N is set to match the currently
    loaded architecture."""

    _cmdline_ = "pattern create"
    _syntax_  = f"{_cmdline_} [-h] [-n N] [length]"
    _example_ = f"{_cmdline_} 4096"

    @parse_arguments({"length": 0}, {("-n", "--n"): 0})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args : argparse.Namespace = kwargs["arguments"]
        length = args.length or gef.config["pattern.length"]
        n = args.n or gef.arch.ptrsize
        info(f"Generating a pattern of {length:d} bytes (n={n:d})")
        pattern_str = gef_pystring(generate_cyclic_pattern(length, n))
        gef_print(pattern_str)
        ok(f"Saved as '{gef_convenience(pattern_str)}'")
        return


@register
class PatternSearchCommand(GenericCommand):
    """Search a De Bruijn Sequence of unique substrings of length N and a
    maximum total length of MAX_LENGTH. The default value of N is set to match
    the currently loaded architecture. The PATTERN argument can be a GDB symbol
    (such as a register name), a string or a hexadecimal value"""

    _cmdline_ = "pattern search"
    _syntax_  = f"{_cmdline_} [-h] [-n N] [--max-length MAX_LENGTH] [pattern]"
    _example_ = [f"{_cmdline_} $pc",
                 f"{_cmdline_} 0x61616164",
                 f"{_cmdline_} aaab"]
    _aliases_ = ["pattern offset"]

    @only_if_gdb_running
    @parse_arguments({"pattern": ""}, {("--period", "-n"): 0, ("--max-length", "-l"): 0})
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        args = kwargs["arguments"]
        if not args.pattern:
            warn("No pattern provided")
            return

        max_length = args.max_length or gef.config["pattern.length"]
        n = args.period or gef.arch.ptrsize
        if n not in (2, 4, 8) or n > gef.arch.ptrsize:
            err("Incorrect value for period")
            return
        self.search(args.pattern, max_length, n)
        return

    def search(self, pattern: str, size: int, period: int) -> None:
        pattern_be, pattern_le = None, None

        # 1. check if it's a symbol (like "$sp" or "0x1337")
        symbol = safe_parse_and_eval(pattern)
        if symbol:
            addr = int(abs(symbol))
            dereferenced_value = dereference(addr)
            if dereferenced_value:
                addr = int(abs(dereferenced_value))
            mask = (1<<(8 * period))-1
            addr &= mask
            pattern_le = addr.to_bytes(period, 'little')
            pattern_be = addr.to_bytes(period, 'big')
        else:
            # 2. assume it's a plain string
            pattern_be = gef_pybytes(pattern)
            pattern_le = gef_pybytes(pattern[::-1])

        info(f"Searching for '{pattern_le.hex()}'/'{pattern_be.hex()}' with period={period}")
        cyclic_pattern = generate_cyclic_pattern(size, period)
        off = cyclic_pattern.find(pattern_le)
        if off >= 0:
            ok(f"Found at offset {off:d} (little-endian search) "
               f"{Color.colorify('likely', 'bold red') if gef.arch.endianness == Endianness.LITTLE_ENDIAN else ''}")
            return

        off = cyclic_pattern.find(pattern_be)
        if off >= 0:
            ok(f"Found at offset {off:d} (big-endian search) "
               f"{Color.colorify('likely', 'bold green') if gef.arch.endianness == Endianness.BIG_ENDIAN else ''}")
            return

        err(f"Pattern '{pattern}' not found")
        return


@register
class ChecksecCommand(GenericCommand):
    """Checksec the security properties of the current executable or passed as argument. The
    command checks for the following protections:
    - PIE
    - NX
    - RelRO
    - Glibc Stack Canaries
    - Fortify Source"""

    _cmdline_ = "checksec"
    _syntax_  = f"{_cmdline_} [FILENAME]"
    _example_ = f"{_cmdline_} /bin/ls"

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def do_invoke(self, argv: List[str]) -> None:
        argc = len(argv)

        if argc == 0:
            filename = get_filepath()
            if filename is None:
                warn("No executable/library specified")
                return
        elif argc == 1:
            filename = os.path.realpath(os.path.expanduser(argv[0]))
            if not os.access(filename, os.R_OK):
                err("Invalid filename")
                return
        else:
            self.usage()
            return

        info(f"{self._cmdline_} for '{filename}'")
        self.print_security_properties(filename)
        return

    def print_security_properties(self, filename: str) -> None:
        sec = Elf(filename).checksec
        for prop in sec:
            if prop in ("Partial RelRO", "Full RelRO"): continue
            val = sec[prop]
            msg = Color.greenify(Color.boldify(TICK)) if val is True else Color.redify(Color.boldify(CROSS))
            if val and prop == "Canary" and is_alive():
                canary = gef.session.canary[0] if gef.session.canary else 0
                msg += f"(value: {canary:#x})"

            gef_print(f"{prop:<30s}: {msg}")

        if sec["Full RelRO"]:
            gef_print(f"{'RelRO':<30s}: {Color.greenify('Full')}")
        elif sec["Partial RelRO"]:
            gef_print(f"{'RelRO':<30s}: {Color.yellowify('Partial')}")
        else:
            gef_print(f"{'RelRO':<30s}: {Color.redify(Color.boldify(CROSS))}")
        return


@register
class GotCommand(GenericCommand):
    """Display current status of the got inside the process."""

    _cmdline_ = "got"
    _syntax_ = f"{_cmdline_} [FUNCTION_NAME ...] "
    _example_ = "got read printf exit"

    def __init__(self):
        super().__init__()
        self["function_resolved"] = ("green",
                                     "Line color of the got command output for resolved function")
        self["function_not_resolved"] = ("yellow",
                                         "Line color of the got command output for unresolved function")
        return

    @only_if_gdb_running
    def do_invoke(self, argv: List[str]) -> None:
        readelf = gef.session.constants["readelf"]

        if is_remote_debug():
            elf_file = str(gef.session.remote.lfile)
            elf_virtual_path = str(gef.session.remote.file)
        else:
            elf_file = str(gef.session.file)
            elf_virtual_path = str(gef.session.file)

        func_names_filter = argv if argv else []
        vmmap = gef.memory.maps
        base_address = min(x.page_start for x in vmmap if x.path == elf_virtual_path)
        end_address = max(x.page_end for x in vmmap if x.path == elf_virtual_path)

        # get the checksec output.
        checksec_status = Elf(elf_file).checksec
        relro_status = "Full RelRO"
        full_relro = checksec_status["Full RelRO"]
        pie = checksec_status["PIE"]  # if pie we will have offset instead of abs address.

        if not full_relro:
            relro_status = "Partial RelRO"
            partial_relro = checksec_status["Partial RelRO"]

            if not partial_relro:
                relro_status = "No RelRO"

        # retrieve jump slots using readelf
        lines = gef_execute_external([readelf, "--relocs", elf_file], as_list=True)
        jmpslots = [line for line in lines if "JUMP" in line]

        gef_print(f"\nGOT protection: {relro_status} | GOT functions: {len(jmpslots)}\n ")

        for line in jmpslots:
            address, _, _, _, name = line.split()[:5]

            # if we have a filter let's skip the entries that are not requested.
            if func_names_filter:
                if not any(map(lambda x: x in name, func_names_filter)):
                    continue

            address_val = int(address, 16)

            # address_val is an offset from the base_address if we have PIE.
            if pie or is_remote_debug():
                address_val = base_address + address_val

            # read the address of the function.
            got_address = gef.memory.read_integer(address_val)

            # for the swag: different colors if the function has been resolved or not.
            if base_address < got_address < end_address:
                color = self["function_not_resolved"]
            else:
                color = self["function_resolved"]

            line = f"[{hex(address_val)}] "
            line += Color.colorify(f"{name} {RIGHT_ARROW} {hex(got_address)}", color)
            gef_print(line)
        return


@register
class HighlightCommand(GenericCommand):
    """Highlight user-defined text matches in GEF output universally."""
    _cmdline_ = "highlight"
    _syntax_ = f"{_cmdline_} (add|remove|list|clear)"
    _aliases_ = ["hl"]

    def __init__(self) -> None:
        super().__init__(prefix=True)
        self["regex"] = (False, "Enable regex highlighting")

    def do_invoke(self, _: List[str]) -> None:
        return self.usage()


@register
class HighlightListCommand(GenericCommand):
    """Show the current highlight table with matches to colors."""
    _cmdline_ = "highlight list"
    _aliases_ = ["highlight ls", "hll"]
    _syntax_ = _cmdline_

    def print_highlight_table(self) -> None:
        if not gef.ui.highlight_table:
            err("no matches found")
            return

        left_pad = max(map(len, gef.ui.highlight_table.keys()))
        for match, color in sorted(gef.ui.highlight_table.items()):
            print(f"{Color.colorify(match.ljust(left_pad), color)} {VERTICAL_LINE} "
                  f"{Color.colorify(color, color)}")
        return

    def do_invoke(self, _: List[str]) -> None:
        return self.print_highlight_table()


@register
class HighlightClearCommand(GenericCommand):
    """Clear the highlight table, remove all matches."""
    _cmdline_ = "highlight clear"
    _aliases_ = ["hlc"]
    _syntax_ = _cmdline_

    def do_invoke(self, _: List[str]) -> None:
        return gef.ui.highlight_table.clear()


@register
class HighlightAddCommand(GenericCommand):
    """Add a match to the highlight table."""
    _cmdline_ = "highlight add"
    _syntax_ = f"{_cmdline_} MATCH COLOR"
    _aliases_ = ["highlight set", "hla"]
    _example_ = f"{_cmdline_} 41414141 yellow"

    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) < 2:
            return self.usage()

        match, color = argv
        gef.ui.highlight_table[match] = color
        return


@register
class HighlightRemoveCommand(GenericCommand):
    """Remove a match in the highlight table."""
    _cmdline_ = "highlight remove"
    _syntax_ = f"{_cmdline_} MATCH"
    _aliases_ = [
        "highlight delete",
        "highlight del",
        "highlight unset",
        "highlight rm",
        "hlr",
    ]
    _example_ = f"{_cmdline_} remove 41414141"

    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            return self.usage()

        gef.ui.highlight_table.pop(argv[0], None)
        return


@register
class FormatStringSearchCommand(GenericCommand):
    """Exploitable format-string helper: this command will set up specific breakpoints
    at well-known dangerous functions (printf, snprintf, etc.), and check if the pointer
    holding the format string is writable, and therefore susceptible to format string
    attacks if an attacker can control its content."""
    _cmdline_ = "format-string-helper"
    _syntax_ = _cmdline_
    _aliases_ = ["fmtstr-helper",]

    def do_invoke(self, _: List[str]) -> None:
        dangerous_functions = {
            "printf": 0,
            "sprintf": 1,
            "fprintf": 1,
            "snprintf": 2,
            "vsnprintf": 2,
        }

        nb_installed_breaks = 0

        with RedirectOutputContext(to_file="/dev/null"):
            for function_name in dangerous_functions:
                argument_number = dangerous_functions[function_name]
                FormatStringBreakpoint(function_name, argument_number)
                nb_installed_breaks += 1

        ok(f"Enabled {nb_installed_breaks} FormatString "
           f"breakpoint{'s' if nb_installed_breaks > 1 else ''}")
        return


@register
class HeapAnalysisCommand(GenericCommand):
    """Heap vulnerability analysis helper: this command aims to track dynamic heap allocation
    done through malloc()/free() to provide some insights on possible heap vulnerabilities. The
    following vulnerabilities are checked:
    - NULL free
    - Use-after-Free
    - Double Free
    - Heap overlap"""
    _cmdline_ = "heap-analysis-helper"
    _syntax_ = _cmdline_

    def __init__(self) -> None:
        super().__init__(complete=gdb.COMPLETE_NONE)
        self["check_free_null"] = (False, "Break execution when a free(NULL) is encountered")
        self["check_double_free"] = (True, "Break execution when a double free is encountered")
        self["check_weird_free"] = (True, "Break execution when free() is called against a non-tracked pointer")
        self["check_uaf"] = (True, "Break execution when a possible Use-after-Free condition is found")
        self["check_heap_overlap"] = (True, "Break execution when a possible overlap in allocation is found")

        self.bp_malloc = None
        self.bp_calloc = None
        self.bp_free = None
        self.bp_realloc = None
        return

    @only_if_gdb_running
    @experimental_feature
    def do_invoke(self, argv: List[str]) -> None:
        if not argv:
            self.setup()
            return

        if argv[0] == "show":
            self.dump_tracked_allocations()
        return

    def setup(self) -> None:
        ok("Tracking malloc() & calloc()")
        self.bp_malloc = TraceMallocBreakpoint("__libc_malloc")
        self.bp_calloc = TraceMallocBreakpoint("__libc_calloc")
        ok("Tracking free()")
        self.bp_free = TraceFreeBreakpoint()
        ok("Tracking realloc()")
        self.bp_realloc = TraceReallocBreakpoint()

        ok("Disabling hardware watchpoints (this may increase the latency)")
        gdb.execute("set can-use-hw-watchpoints 0")

        info("Dynamic breakpoints correctly setup, "
             "GEF will break execution if a possible vulnerabity is found.")
        warn(f"{Color.colorify('Note', 'bold underline yellow')}: "
             "The heap analysis slows down the execution noticeably.")

        # when inferior quits, we need to clean everything for a next execution
        gef_on_exit_hook(self.clean)
        return

    def dump_tracked_allocations(self) -> None:
        global gef

        if gef.session.heap_allocated_chunks:
            ok("Tracked as in-use chunks:")
            for addr, sz in gef.session.heap_allocated_chunks:
                gef_print(f"{CROSS} malloc({sz:d}) = {addr:#x}")
        else:
            ok("No malloc() chunk tracked")

        if gef.session.heap_freed_chunks:
            ok("Tracked as free-ed chunks:")
            for addr, sz in gef.session.heap_freed_chunks:
                gef_print(f"{TICK}  free({sz:d}) = {addr:#x}")
        else:
            ok("No free() chunk tracked")
        return

    def clean(self, _: "gdb.Event") -> None:
        global gef

        ok(f"{Color.colorify('Heap-Analysis', 'yellow bold')} - Cleaning up")
        for bp in [self.bp_malloc, self.bp_calloc, self.bp_free, self.bp_realloc]:
            if hasattr(bp, "retbp") and bp.retbp:
                try:
                    bp.retbp.delete()
                except RuntimeError:
                    # in some cases, gdb was found failing to correctly remove the retbp
                    # but they can be safely ignored since the debugging session is over
                    pass

            bp.delete()

        for wp in gef.session.heap_uaf_watchpoints:
            wp.delete()

        gef.session.heap_allocated_chunks = []
        gef.session.heap_freed_chunks = []
        gef.session.heap_uaf_watchpoints = []

        ok(f"{Color.colorify('Heap-Analysis', 'yellow bold')} - Re-enabling hardware watchpoints")
        gdb.execute("set can-use-hw-watchpoints 1")

        gef_on_exit_unhook(self.clean)
        return


#
# GDB Function declaration
#
@deprecated("")
def register_function(cls: Type["GenericFunction"]) -> Type["GenericFunction"]:
    """Decorator for registering a new convenience function to GDB."""
    return cls


class GenericFunction(gdb.Function):
    """This is an abstract class for invoking convenience functions, should not be instantiated."""

    _function_ : str
    _syntax_: str = ""
    _example_ : str = ""

    def __init__(self) -> None:
        super().__init__(self._function_)

    def invoke(self, *args: Any) -> int:
        if not is_alive():
            raise gdb.GdbError("No debugging session active")
        return self.do_invoke(args)

    def arg_to_long(self, args: List, index: int, default: int = 0) -> int:
        try:
            addr = args[index]
            return int(addr) if addr.address is None else int(addr.address)
        except IndexError:
            return default

    def do_invoke(self, args: Any) -> int:
        raise NotImplementedError


@register
class StackOffsetFunction(GenericFunction):
    """Return the current stack base address plus an optional offset."""
    _function_ = "_stack"
    _syntax_   = f"${_function_}()"

    def do_invoke(self, args: List) -> int:
        base = get_section_base_address("[stack]")
        if not base:
            raise gdb.GdbError("Stack not found")

        return self.arg_to_long(args, 0) + base


@register
class HeapBaseFunction(GenericFunction):
    """Return the current heap base address plus an optional offset."""
    _function_ = "_heap"
    _syntax_   = f"${_function_}()"

    def do_invoke(self, args: List) -> int:
        base = gef.heap.base_address
        if not base:
            base = get_section_base_address("[heap]")
            if not base:
                raise gdb.GdbError("Heap not found")
        return self.arg_to_long(args, 0) + base


@register
class SectionBaseFunction(GenericFunction):
    """Return the matching file's base address plus an optional offset.
    Defaults to current file. Note that quotes need to be escaped"""
    _function_ = "_base"
    _syntax_   = "$_base([filepath])"
    _example_  = "p $_base(\\\"/usr/lib/ld-2.33.so\\\")"

    def do_invoke(self, args: List) -> int:
        addr = 0
        try:
            name = args[0].string()
        except IndexError:
            name = gef.session.file.name
        except gdb.error:
            err(f"Invalid arg: {args[0]}")
            return 0

        try:
            base = get_section_base_address(name)
            if base:
                addr = int(base)
        except TypeError:
            err(f"Cannot find section {name}")
            return 0
        return addr


@register
class BssBaseFunction(GenericFunction):
    """Return the current bss base address plus the given offset."""
    _function_ = "_bss"
    _syntax_   = f"${_function_}([OFFSET])"
    _example_ = "deref $_bss(0x20)"

    def do_invoke(self, args: List) -> int:
        base = get_zone_base_address(".bss")
        if not base:
            raise gdb.GdbError("BSS not found")
        return self.arg_to_long(args, 0) + base


@register
class GotBaseFunction(GenericFunction):
    """Return the current GOT base address plus the given offset."""
    _function_ = "_got"
    _syntax_   = f"${_function_}([OFFSET])"
    _example_ = "deref $_got(0x20)"

    def do_invoke(self, args: List) -> int:
        base = get_zone_base_address(".got")
        if not base:
            raise gdb.GdbError("GOT not found")
        return base + self.arg_to_long(args, 0)


@register
class GefFunctionsCommand(GenericCommand):
    """List the convenience functions provided by GEF."""
    _cmdline_ = "functions"
    _syntax_ = _cmdline_

    def __init__(self) -> None:
        super().__init__()
        self.docs = []
        self.should_refresh = True
        return

    def __add__(self, function: GenericFunction):
        """Add function to documentation."""
        doc = getattr(function, "__doc__", "").lstrip()
        if not hasattr(function, "_syntax_"):
            raise ValueError("Function is invalid")
        syntax = getattr(function, "_syntax_").lstrip()
        msg = f"{Color.colorify(syntax, 'bold cyan')}\n {doc}"
        example = getattr(function, "_example_", "").strip()
        if example:
            msg += f"\n {Color.yellowify('Example:')} {example}"
        self.docs.append(msg)
        return self

    def __radd__(self, function: GenericFunction):
        return self.__add__(function)

    def __str__(self) -> str:
        if self.should_refresh:
            self.__rebuild()
        return self.__doc__ or ""

    def __rebuild(self) -> None:
        """Rebuild the documentation for functions."""
        for function in gef.gdb.functions.values():
            self += function

        self.command_size = len(gef.gdb.commands)
        _, cols = get_terminal_size()
        separator = HORIZONTAL_LINE*cols
        self.__doc__ = f"\n{separator}\n".join(sorted(self.docs))
        self.should_refresh = False
        return

    def do_invoke(self, argv) -> None:
        self.dont_repeat()
        gef_print(titlify("GEF - Convenience Functions"))
        gef_print("These functions can be used as arguments to other "
                  "commands to dynamically calculate values\n")
        gef_print(str(self))
        return


#
# GEF internal command classes
#
class GefCommand(gdb.Command):
    """GEF main command: view all new commands by typing `gef`."""

    _cmdline_ = "gef"
    _syntax_  = f"{_cmdline_} (missing|config|save|restore|set|run)"

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)
        gef.config["gef.follow_child"] = GefSetting(True, bool, "Automatically set GDB to follow child when forking")
        gef.config["gef.readline_compat"] = GefSetting(False, bool, "Workaround for readline SOH/ETX issue (SEGV)")
        gef.config["gef.debug"] = GefSetting(False, bool, "Enable debug mode for gef")
        gef.config["gef.autosave_breakpoints_file"] = GefSetting("", str, "Automatically save and restore breakpoints")
        plugins_dir = GefSetting("", str, "Autoload additional GEF commands from external directory", hooks={"on_write": GefSetting.no_spaces})
        plugins_dir.add_hook("on_write", lambda _: self.load_extra_plugins())
        gef.config["gef.extra_plugins_dir"] = plugins_dir
        gef.config["gef.disable_color"] = GefSetting(False, bool, "Disable all colors in GEF")
        gef.config["gef.tempdir"] = GefSetting(GEF_TEMP_DIR, str, "Directory to use for temporary/cache content", hooks={"on_write": GefSetting.no_spaces})
        gef.config["gef.show_deprecation_warnings"] = GefSetting(True, bool, "Toggle the display of the `deprecated` warnings")
        gef.config["gef.buffer"] = GefSetting(True, bool, "Internally buffer command output until completion")
        gef.config["gef.bruteforce_main_arena"] = GefSetting(False, bool, "Allow bruteforcing main_arena symbol if everything else fails")
        gef.config["gef.main_arena_offset"] = GefSetting("", str, "Offset from libc base address to main_arena symbol (int or hex). Set to empty string to disable.")

        self.commands : Dict[str, GenericCommand] = collections.OrderedDict()
        self.functions : Dict[str, GenericFunction] = collections.OrderedDict()
        self.missing: Dict[str, Exception] = {}
        return

    @property
    def loaded_commands(self) -> List[Tuple[str, Type[GenericCommand], Any]]:
        print("Obsolete loaded_commands")
        raise

    @property
    def loaded_functions(self) -> List[Type[GenericFunction]]:
        print("Obsolete loaded_functions")
        raise

    @property
    def missing_commands(self) -> Dict[str, Exception]:
        print("Obsolete missing_commands")
        raise

    def setup(self) -> None:
        self.load()

        GefHelpCommand()
        GefConfigCommand()
        GefSaveCommand()
        GefMissingCommand()
        GefSetCommand()
        GefRunCommand()
        GefInstallExtraScriptCommand()

        # restore the settings from config file if any
        GefRestoreCommand()
        return

    def load_extra_plugins(self) -> int:
        def load_plugin(fpath: pathlib.Path) -> bool:
            try:
                dbg(f"Loading '{fpath}'")
                gdb.execute(f"source {fpath}")
            except Exception as e:
                warn(f"Exception while loading {fpath}: {str(e)}")
                return False
            return True

        nb_added = -1
        start_time = time.perf_counter()
        try:
            nb_inital = len(__registered_commands__)
            directories: List[str] = gef.config["gef.extra_plugins_dir"].split(";") or []
            for d in directories:
                d = d.strip()
                if not d: continue
                directory = pathlib.Path(d).expanduser()
                if not directory.is_dir(): continue
                sys.path.append(str(directory.absolute()))
                for entry in directory.iterdir():
                    if entry.is_dir():
                        if entry.name in ('gdb', 'gef', '__pycache__'): continue
                        load_plugin(entry / "__init__.py")
                    else:
                        if entry.suffix != ".py": continue
                        if entry.name == "__init__.py": continue
                        load_plugin(entry)

            nb_added = len(__registered_commands__) - nb_inital
            if nb_added > 0:
                self.load()
                nb_failed = len(__registered_commands__) - len(self.commands)
                end_time = time.perf_counter()
                load_time = end_time - start_time
                ok(f"{Color.colorify(str(nb_added), 'bold green')} extra commands added from "
                   f"'{Color.colorify(', '.join(directories), 'bold blue')}' in {load_time:.2f} seconds")
                if nb_failed != 0:
                    warn(f"{Color.colorify(str(nb_failed), 'bold light_gray')} extra commands/functions failed to be added. "
                    "Check `gef missing` to know why")

        except gdb.error as e:
            err(f"failed: {e}")
        return nb_added

    @property
    def loaded_command_names(self) -> Iterable[str]:
        print("obsolete loaded_command_names")
        return self.commands.keys()

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()
        gdb.execute("gef help")
        return

    def add_context_pane(self, pane_name: str, display_pane_function: Callable, pane_title_function: Callable, condition: Optional[Callable]) -> None:
        """Add a new context pane to ContextCommand."""
        for _, class_instance in self.commands.items():
            if isinstance(class_instance, ContextCommand):
                context = class_instance
                break
        else:
            err("Cannot find ContextCommand")
            return

        # assure users can toggle the new context
        corrected_settings_name = pane_name.replace(" ", "_")
        gef.config["context.layout"] += f" {corrected_settings_name}"

        # overload the printing of pane title
        context.layout_mapping[corrected_settings_name] = (display_pane_function, pane_title_function, condition)

    def load(self) -> None:
        """Load all the commands and functions defined by GEF into GDB."""
        current_commands = set(self.commands.keys())
        new_commands = set(x._cmdline_ for x in __registered_commands__) - current_commands
        current_functions = set(self.functions.keys())
        new_functions = set(x._function_ for x in __registered_functions__) - current_functions
        self.missing.clear()
        self.__load_time_ms = time.time()* 1000

        # load all new functions
        for name in sorted(new_functions):
            for function_cls in __registered_functions__:
                if function_cls._function_ == name:
                    self.functions[name] = function_cls()
                    break

        # load all new commands
        for name in sorted(new_commands):
            try:
                for command_cls in __registered_commands__:
                    if command_cls._cmdline_ == name:
                        command_instance = command_cls()

                        # create the aliases if any
                        if hasattr(command_instance, "_aliases_"):
                            aliases = getattr(command_instance, "_aliases_")
                            for alias in aliases:
                                GefAlias(alias, name)

                        self.commands[name] = command_instance
                        break

            except Exception as reason:
                self.missing[name] = reason

        self.__load_time_ms = (time.time()* 1000) - self.__load_time_ms
        return


    def show_banner(self) -> None:
        gef_print(f"{Color.greenify('GEF')} for {gef.session.os} ready, "
                  f"type `{Color.colorify('gef', 'underline yellow')}' to start, "
                  f"`{Color.colorify('gef config', 'underline pink')}' to configure")

        ver = f"{sys.version_info.major:d}.{sys.version_info.minor:d}"
        gef_print(f"{Color.colorify(str(len(self.commands)), 'bold green')} commands loaded "
                    f"and {Color.colorify(str(len(self.functions)), 'bold blue')} functions added for "
                    f"GDB {Color.colorify(gdb.VERSION, 'bold yellow')} in {self.__load_time_ms:.2f}ms "
                    f"using Python engine {Color.colorify(ver, 'bold red')}")

        nb_missing = len(self.missing)
        if nb_missing:
                warn(f"{Color.colorify(str(nb_missing), 'bold red')} "
                    f"command{'s' if nb_missing > 1 else ''} could not be loaded, "
                    f"run `{Color.colorify('gef missing', 'underline pink')}` to know why.")
        return


class GefHelpCommand(gdb.Command):
    """GEF help sub-command."""
    _cmdline_ = "gef help"
    _syntax_  = _cmdline_

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, False)
        self.docs = []
        self.should_refresh = True
        self.command_size = 0
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()
        gef_print(titlify("GEF - GDB Enhanced Features"))
        gef_print(str(self))
        return

    def __rebuild(self) -> None:
        """Rebuild the documentation."""
        for name, cmd in gef.gdb.commands.items():
            self += (name, cmd)

        self.command_size = len(gef.gdb.commands)
        _, cols = get_terminal_size()
        separator = HORIZONTAL_LINE*cols
        self.__doc__ = f"\n{separator}\n".join(sorted(self.docs))
        self.should_refresh = False
        return

    def __add__(self, command: Tuple[str, GenericCommand]):
        """Add command to GEF documentation."""
        cmd, class_obj = command
        if " " in cmd:
            # do not print subcommands in gef help
            return self
        doc = getattr(class_obj, "__doc__", "").lstrip()
        aliases = f"Aliases: {', '.join(class_obj._aliases_)}" if hasattr(class_obj, "_aliases_") else ""
        msg = f"{Color.colorify(cmd, 'bold red')}\n{doc}\n{aliases}"
        self.docs.append(msg)
        return self

    def __radd__(self, command: Tuple[str, GenericCommand]):
        return self.__add__(command)

    def __str__(self) -> str:
        """Lazily regenerate the `gef help` object if it was modified"""
        # quick check in case the docs have changed
        if self.should_refresh or self.command_size != len(gef.gdb.commands):
            self.__rebuild()
        return self.__doc__ or ""


class GefConfigCommand(gdb.Command):
    """GEF configuration sub-command
    This command will help set/view GEF settings for the current debugging session.
    It is possible to make those changes permanent by running `gef save` (refer
    to this command help), and/or restore previously saved settings by running
    `gef restore` (refer help).
    """
    _cmdline_ = "gef config"
    _syntax_  = f"{_cmdline_} [setting_name] [setting_value]"

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_NONE, prefix=False)
        return

    def invoke(self, args: str, from_tty: bool) -> None:
        self.dont_repeat()
        argv = gdb.string_to_argv(args)
        argc = len(argv)

        if not (0 <= argc <= 2):
            err("Invalid number of arguments")
            return

        if argc == 0:
            gef_print(titlify("GEF configuration settings"))
            self.print_settings()
            return

        if argc == 1:
            prefix = argv[0]
            names = [x for x in gef.config.keys() if x.startswith(prefix)]
            if names:
                if len(names) == 1:
                    gef_print(titlify(f"GEF configuration setting: {names[0]}"))
                    self.print_setting(names[0], verbose=True)
                else:
                    gef_print(titlify(f"GEF configuration settings matching '{argv[0]}'"))
                    for name in names: self.print_setting(name)
            return

        self.set_setting(argv)
        return

    def print_setting(self, plugin_name: str, verbose: bool = False) -> None:
        res = gef.config.raw_entry(plugin_name)
        string_color = gef.config["theme.dereference_string"]
        misc_color = gef.config["theme.dereference_base_address"]

        if not res:
            return

        _setting = Color.colorify(plugin_name, "green")
        _type = res.type.__name__
        if _type == "str":
            _value = f'"{Color.colorify(res.value, string_color)}"'
        else:
            _value = Color.colorify(res.value, misc_color)

        gef_print(f"{_setting} ({_type}) = {_value}")

        if verbose:
            gef_print(Color.colorify("\nDescription:", "bold underline"))
            gef_print(f"\t{res.description}")
        return

    def print_settings(self) -> None:
        for x in sorted(gef.config):
            self.print_setting(x)
        return

    def set_setting(self, argv: Tuple[str, Any]) -> None:
        global gef
        key, new_value = argv

        if "." not in key:
            err("Invalid command format")
            return

        loaded_commands = list( gef.gdb.commands.keys()) + ["gef"]
        plugin_name = key.split(".", 1)[0]
        if plugin_name not in loaded_commands:
            err(f"Unknown plugin '{plugin_name}'")
            return

        if key not in gef.config:
            err(f"'{key}' is not a valid configuration setting")
            return

        _type = gef.config.raw_entry(key).type
        try:
            if _type == bool:
                if new_value.upper() in ("TRUE", "T", "1"):
                    _newval = True
                elif new_value.upper() in ("FALSE", "F", "0"):
                    _newval = False
                else:
                    raise ValueError(f"cannot parse '{new_value}' as bool")
            else:
                _newval = new_value
        except Exception as e:
            err(f"'{key}' expects type '{_type.__name__}', got {type(new_value).__name__}: reason {str(e)}")
            return

        try:
            gef.config[key] = _newval
        except Exception as e:
            err(f"Cannot set '{key}': {e}")

        reset_all_caches()
        return

    def complete(self, text: str, word: str) -> List[str]:
        settings = sorted(gef.config)

        if text == "":
            # no prefix: example: `gef config TAB`
            return [s for s in settings if word in s]

        if "." not in text:
            # if looking for possible prefix
            return [s for s in settings if s.startswith(text.strip())]

        # finally, look for possible values for given prefix
        return [s.split(".", 1)[1] for s in settings if s.startswith(text.strip())]


class GefSaveCommand(gdb.Command):
    """GEF save sub-command.
    Saves the current configuration of GEF to disk (by default in file '~/.gef.rc')."""
    _cmdline_ = "gef save"
    _syntax_  = _cmdline_

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, False)
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()
        cfg = configparser.RawConfigParser()
        old_sect = None

        # save the configuration
        for key in sorted(gef.config):
            sect, optname = key.split(".", 1)
            value = gef.config[key]

            if old_sect != sect:
                cfg.add_section(sect)
                old_sect = sect

            cfg.set(sect, optname, value)

        # save the aliases
        cfg.add_section("aliases")
        for alias in gef.session.aliases:
            cfg.set("aliases", alias._alias, alias._command)

        with GEF_RC.open("w") as fd:
            cfg.write(fd)

        ok(f"Configuration saved to '{GEF_RC}'")
        return


class GefRestoreCommand(gdb.Command):
    """GEF restore sub-command.
    Loads settings from file '~/.gef.rc' and apply them to the configuration of GEF."""
    _cmdline_ = "gef restore"
    _syntax_  = _cmdline_

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, False)
        self.reload(True)
        return

    def invoke(self, args: str, from_tty: bool) -> None:
        self.dont_repeat()
        if  GEF_RC.is_file():
            quiet = (args.lower() == "quiet")
            self.reload(quiet)
        return

    def reload(self, quiet: bool):
        cfg = configparser.ConfigParser()
        cfg.read(GEF_RC)

        for section in cfg.sections():
            if section == "aliases":
                # load the aliases
                for key in cfg.options(section):
                    try:
                        GefAlias(key, cfg.get(section, key))
                    except:
                        pass
                continue

            # load the other options
            for optname in cfg.options(section):
                key = f"{section}.{optname}"
                try:
                    setting = gef.config.raw_entry(key)
                except Exception:
                    continue
                new_value = cfg.get(section, optname)
                if setting.type == bool:
                    new_value = True if new_value.upper() in ("TRUE", "T", "1") else False
                setting.value = setting.type(new_value)

        if not quiet:
            ok(f"Configuration from '{Color.colorify(str(GEF_RC), 'bold blue')}' restored")
        return


class GefMissingCommand(gdb.Command):
    """GEF missing sub-command
    Display the GEF commands that could not be loaded, along with the reason of why
    they could not be loaded.
    """
    _cmdline_ = "gef missing"
    _syntax_  = _cmdline_

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, False)
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()
        missing_commands = gef.gdb.missing
        if not missing_commands:
            ok("No missing command")
            return

        for missing_command, reason in missing_commands.items():
            warn(f"Command `{missing_command}` is missing, reason {RIGHT_ARROW} {reason}")
        return


class GefSetCommand(gdb.Command):
    """Override GDB set commands with the context from GEF."""
    _cmdline_ = "gef set"
    _syntax_  = f"{_cmdline_} [GDB_SET_ARGUMENTS]"

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_SYMBOL, False)
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()
        args = args.split()
        cmd = ["set", args[0],]
        for p in args[1:]:
            if p.startswith("$_gef"):
                c = gdb.parse_and_eval(p)
                cmd.append(c.string())
            else:
                cmd.append(p)

        gdb.execute(" ".join(cmd))
        return


class GefRunCommand(gdb.Command):
    """Override GDB run commands with the context from GEF.
    Simple wrapper for GDB run command to use arguments set from `gef set args`."""
    _cmdline_ = "gef run"
    _syntax_  = f"{_cmdline_} [GDB_RUN_ARGUMENTS]"

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_FILENAME, False)
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()
        if is_alive():
            gdb.execute("continue")
            return

        argv = args.split()
        gdb.execute(f"gef set args {' '.join(argv)}")
        gdb.execute("run")
        return


class GefAlias(gdb.Command):
    """Simple aliasing wrapper because GDB doesn't do what it should."""

    def __init__(self, alias: str, command: str, completer_class: int = gdb.COMPLETE_NONE, command_class: int = gdb.COMMAND_NONE) -> None:
        p = command.split()
        if not p:
            return

        if any(x for x in gef.session.aliases if x._alias == alias):
            return

        self._command = command
        self._alias = alias
        c = command.split()[0]
        r = self.lookup_command(c)
        self.__doc__ = f"Alias for '{Color.greenify(command)}'"
        if r is not None:
            _instance = r[1]
            self.__doc__ += f": {_instance.__doc__}"

            if hasattr(_instance,  "complete"):
                self.complete = _instance.complete

        super().__init__(alias, command_class, completer_class=completer_class)
        gef.session.aliases.append(self)
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        gdb.execute(f"{self._command} {args}", from_tty=from_tty)
        return

    def lookup_command(self, cmd: str) -> Optional[Tuple[str, GenericCommand]]:
        global gef
        for _name, _instance in gef.gdb.commands.items():
            if cmd == _name:
                return _name, _instance

        return None


@register
class AliasesCommand(GenericCommand):
    """Base command to add, remove, or list aliases."""

    _cmdline_ = "aliases"
    _syntax_  = f"{_cmdline_} (add|rm|ls)"

    def __init__(self) -> None:
        super().__init__(prefix=True)
        return

    def do_invoke(self, _: List[str]) -> None:
        self.usage()
        return


@register
class AliasesAddCommand(AliasesCommand):
    """Command to add aliases."""

    _cmdline_ = "aliases add"
    _syntax_  = f"{_cmdline_} [ALIAS] [COMMAND]"
    _example_ = f"{_cmdline_} scope telescope"

    def __init__(self) -> None:
        super().__init__()
        return

    def do_invoke(self, argv: List[str]) -> None:
        if len(argv) < 2:
            self.usage()
            return
        GefAlias(argv[0], " ".join(argv[1:]))
        return


@register
class AliasesRmCommand(AliasesCommand):
    """Command to remove aliases."""

    _cmdline_ = "aliases rm"
    _syntax_ = f"{_cmdline_} [ALIAS]"

    def __init__(self) -> None:
        super().__init__()
        return

    def do_invoke(self, argv: List[str]) -> None:
        global gef
        if len(argv) != 1:
            self.usage()
            return
        try:
            alias_to_remove = next(filter(lambda x: x._alias == argv[0], gef.session.aliases))
            gef.session.aliases.remove(alias_to_remove)
        except (ValueError, StopIteration):
            err(f"{argv[0]} not found in aliases.")
            return
        gef_print("You must reload GEF for alias removals to apply.")
        return


@register
class AliasesListCommand(AliasesCommand):
    """Command to list aliases."""

    _cmdline_ = "aliases ls"
    _syntax_ = _cmdline_

    def __init__(self) -> None:
        super().__init__()
        return

    def do_invoke(self, _: List[str]) -> None:
        ok("Aliases defined:")
        for a in gef.session.aliases:
            gef_print(f"{a._alias:30s} {RIGHT_ARROW} {a._command}")
        return


class GefTmuxSetup(gdb.Command):
    """Setup a confortable tmux debugging environment."""

    def __init__(self) -> None:
        super().__init__("tmux-setup", gdb.COMMAND_NONE, gdb.COMPLETE_NONE)
        GefAlias("screen-setup", "tmux-setup")
        return

    def invoke(self, args: Any, from_tty: bool) -> None:
        self.dont_repeat()

        tmux = os.getenv("TMUX")
        if tmux:
            self.tmux_setup()
            return

        screen = os.getenv("TERM")
        if screen is not None and screen == "screen":
            self.screen_setup()
            return

        warn("Not in a tmux/screen session")
        return

    def tmux_setup(self) -> None:
        """Prepare the tmux environment by vertically splitting the current pane, and
        forcing the context to be redirected there."""
        tmux = which("tmux")
        ok("tmux session found, splitting window...")

        pane, pty = subprocess.check_output([tmux, "splitw", "-h", '-F#{session_name}:#{window_index}.#{pane_index}-#{pane_tty}', "-P"]).decode().strip().split("-")
        atexit.register(lambda : subprocess.run([tmux, "kill-pane", "-t", pane]))
        # clear the screen and let it wait for input forever
        gdb.execute(f"!'{tmux}' send-keys -t {pane} 'clear ; cat' C-m")
        gdb.execute(f"!'{tmux}' select-pane -L")

        ok(f"Setting `context.redirect` to '{pty}'...")
        gdb.execute(f"gef config context.redirect {pty}")
        ok("Done!")
        return

    def screen_setup(self) -> None:
        """Hackish equivalent of the tmux_setup() function for screen."""
        screen = which("screen")
        sty = os.getenv("STY")
        ok("screen session found, splitting window...")
        fd_script, script_path = tempfile.mkstemp()
        fd_tty, tty_path = tempfile.mkstemp()
        os.close(fd_tty)

        with os.fdopen(fd_script, "w") as f:
            f.write("startup_message off\n")
            f.write("split -v\n")
            f.write("focus right\n")
            f.write(f"screen bash -c 'tty > {tty_path}; clear; cat'\n")
            f.write("focus left\n")

        gdb.execute(f"!'{screen}' -r '{sty}' -m -d -X source {script_path}")
        # artificial delay to make sure `tty_path` is populated
        time.sleep(0.25)
        with open(tty_path, "r") as f:
            pty = f.read().strip()
        ok(f"Setting `context.redirect` to '{pty}'...")
        gdb.execute(f"gef config context.redirect {pty}")
        ok("Done!")
        os.unlink(script_path)
        os.unlink(tty_path)
        return


class GefInstallExtraScriptCommand(gdb.Command):
    """`gef install` command: installs one or more scripts from the `gef-extras` script repo. Note that the command
    doesn't check for external dependencies the script(s) might require."""
    _cmdline_ = "gef install"
    _syntax_  = f"{_cmdline_} SCRIPTNAME [SCRIPTNAME [SCRIPTNAME...]]"

    def __init__(self) -> None:
        super().__init__(self._cmdline_, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, False)
        self.branch = gef.config.get("gef.extras_default_branch", GEF_EXTRAS_DEFAULT_BRANCH)
        return

    def invoke(self, argv: str, from_tty: bool) -> None:
        self.dont_repeat()
        if not argv:
            err("No script name provided")
            return

        args = argv.split()

        if "--list" in args or "-l" in args:
            subprocess.run(["xdg-open", f"https://github.com/hugsy/gef-extras/{self.branch}/"])
            return

        self.dirpath = pathlib.Path(gef.config["gef.tempdir"]).expanduser().absolute()
        if not self.dirpath.is_dir():
            err("'gef.tempdir' is not a valid directory")
            return

        for script in args:
            script = script.lower()
            if not self.__install_extras_script(script):
                warn(f"Failed to install '{script}', skipping...")
        return


    def __install_extras_script(self, script: str) -> bool:
        fpath = self.dirpath / f"{script}.py"
        if not fpath.exists():
            url = f"https://raw.githubusercontent.com/hugsy/gef-extras/{self.branch}/scripts/{script}.py"
            info(f"Searching for '{script}.py' in `gef-extras@{self.branch}`...")
            data = http_get(url)
            if not data:
                warn("Not found")
                return False

            with fpath.open("wb") as fd:
                fd.write(data)
                fd.flush()

        old_command_set = set(gef.gdb.commands)
        gdb.execute(f"source {fpath}")
        new_command_set = set(gef.gdb.commands)
        new_commands = [f"`{c[0]}`" for c in (new_command_set - old_command_set)]
        ok(f"Installed file '{fpath}', new command(s) available: {', '.join(new_commands)}")
        return True


#
# GEF internal  classes
#

def __gef_prompt__(current_prompt: Callable[[Callable], str]) -> str:
    """GEF custom prompt function."""
    if gef.config["gef.readline_compat"] is True: return GEF_PROMPT
    if gef.config["gef.disable_color"] is True: return GEF_PROMPT
    prompt = ""
    if gef.session.remote:
        prompt += Color.boldify("(remote) ")
    prompt += GEF_PROMPT_ON if is_alive() else GEF_PROMPT_OFF
    return prompt


class GefManager(metaclass=abc.ABCMeta):
    def reset_caches(self) -> None:
        """Reset the LRU-cached attributes"""
        for attr in dir(self):
            try:
                obj = getattr(self, attr)
                if not hasattr(obj, "cache_clear"):
                    continue
                obj.cache_clear()
            except: # we're reseting the cache here, we don't care if (or which) exception triggers
                continue
        return


class GefMemoryManager(GefManager):
    """Class that manages memory access for gef."""
    def __init__(self) -> None:
        self.reset_caches()
        return

    def reset_caches(self) -> None:
        super().reset_caches()
        self.__maps = None
        return

    def write(self, address: int, buffer: ByteString, length: Optional[int] = None) -> None:
        """Write `buffer` at address `address`."""
        length = length or len(buffer)
        gdb.selected_inferior().write_memory(address, buffer, length)

    def read(self, addr: int, length: int = 0x10) -> bytes:
        """Return a `length` long byte array with the copy of the process memory at `addr`."""
        return gdb.selected_inferior().read_memory(addr, length).tobytes()

    def read_integer(self, addr: int) -> int:
        """Return an integer read from memory."""
        sz = gef.arch.ptrsize
        mem = self.read(addr, sz)
        unpack = u32 if sz == 4 else u64
        return unpack(mem)

    def read_cstring(self,
                     address: int,
                     max_length: int = GEF_MAX_STRING_LENGTH,
                     encoding: Optional[str] = None) -> str:
        """Return a C-string read from memory."""
        encoding = encoding or "unicode-escape"
        length = min(address | (DEFAULT_PAGE_SIZE-1), max_length+1)

        try:
            res_bytes = self.read(address, length)
        except gdb.error:
            err(f"Can't read memory at '{address}'")
            return ""
        try:
            with warnings.catch_warnings():
                # ignore DeprecationWarnings (see #735)
                warnings.simplefilter("ignore")
                res = res_bytes.decode(encoding, "strict")
        except UnicodeDecodeError:
            # latin-1 as fallback due to its single-byte to glyph mapping
            res = res_bytes.decode("latin-1", "replace")

        res = res.split("\x00", 1)[0]
        ustr = res.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        if max_length and len(res) > max_length:
            return f"{ustr[:max_length]}[...]"
        return ustr

    def read_ascii_string(self, address: int) -> Optional[str]:
        """Read an ASCII string from memory"""
        cstr = self.read_cstring(address)
        if isinstance(cstr, str) and cstr and all(x in string.printable for x in cstr):
            return cstr
        return None

    @property
    def maps(self) -> List[Section]:
        if not self.__maps:
            self.__maps = self.__parse_maps()
        return self.__maps

    def __parse_maps(self) -> List[Section]:
        """Return the mapped memory sections"""
        try:
            if is_qemu_system():
                return list(self.__parse_info_mem())
        except gdb.error:
            # Target may not support this command
            pass
        try:
            return list(self.__parse_procfs_maps())
        except FileNotFoundError:
            return list(self.__parse_gdb_info_sections())

    def __parse_procfs_maps(self) -> Generator[Section, None, None]:
        """Get the memory mapping from procfs."""
        procfs_mapfile = gef.session.maps
        if not procfs_mapfile:
            is_remote = gef.session.remote is not None
            raise FileNotFoundError(f"Missing {'remote ' if is_remote else ''}procfs map file")
        with procfs_mapfile.open("r") as fd:
            for line in fd:
                line = line.strip()
                addr, perm, off, _, rest = line.split(" ", 4)
                rest = rest.split(" ", 1)
                if len(rest) == 1:
                    inode = rest[0]
                    pathname = ""
                else:
                    inode = rest[0]
                    pathname = rest[1].lstrip()

                addr_start, addr_end = parse_string_range(addr)
                off = int(off, 16)
                perm = Permission.from_process_maps(perm)
                inode = int(inode)
                yield Section(page_start=addr_start,
                            page_end=addr_end,
                            offset=off,
                            permission=perm,
                            inode=inode,
                            path=pathname)
        return

    def __parse_gdb_info_sections(self) -> Generator[Section, None, None]:
        """Get the memory mapping from GDB's command `maintenance info sections` (limited info)."""
        stream = StringIO(gdb.execute("maintenance info sections", to_string=True))

        for line in stream:
            if not line:
                break

            try:
                parts = [x for x in line.split()]
                addr_start, addr_end = [int(x, 16) for x in parts[1].split("->")]
                off = int(parts[3][:-1], 16)
                path = parts[4]
                perm = Permission.from_info_sections(parts[5:])
                yield Section(
                    page_start=addr_start,
                    page_end=addr_end,
                    offset=off,
                    permission=perm,
                    inode="",
                    path=path
                )

            except IndexError:
                continue
            except ValueError:
                continue
        return

    def __parse_info_mem(self) -> Generator[Section, None, None]:
        """Get the memory mapping from GDB's command `monitor info mem`"""
        for line in StringIO(gdb.execute("monitor info mem", to_string=True)):
            if not line:
                break
            try:
                ranges, off, perms = line.split()
                off = int(off, 16)
                start, end = [int(s, 16) for s in ranges.split("-")]
            except ValueError as e:
                continue

            perm = Permission.from_info_mem(perms)
            yield Section(
                page_start=start,
                page_end=end,
                offset=off,
                permission=perm,
                inode="",
            )


class GefHeapManager(GefManager):
    """Class managing session heap."""
    def __init__(self) -> None:
        self.reset_caches()
        return

    def reset_caches(self) -> None:
        self.__libc_main_arena: Optional[GlibcArena] = None
        self.__libc_selected_arena: Optional[GlibcArena] = None
        self.__heap_base = None
        return

    @property
    def main_arena(self) -> Optional[GlibcArena]:
        if not self.__libc_main_arena:
            try:
                __main_arena_addr = GefHeapManager.find_main_arena_addr()
                self.__libc_main_arena = GlibcArena(f"*{__main_arena_addr:#x}")
                # the initialization of `main_arena` also defined `selected_arena`, so
                # by default, `main_arena` == `selected_arena`
                self.selected_arena = self.__libc_main_arena
            except:
                # the search for arena can fail when the session is not started
                pass
        return self.__libc_main_arena

    @main_arena.setter
    def main_arena(self, value: GlibcArena) -> None:
        self.__libc_main_arena = value
        return

    @staticmethod
    @lru_cache()
    def find_main_arena_addr() -> int:
        assert gef.libc.version
        """A helper function to find the glibc `main_arena` address, either from
        symbol, from its offset from `__malloc_hook` or by brute force."""
        # Before anything else, use libc offset from config if available
        if gef.config["gef.main_arena_offset"]:
            try:
                libc_base = get_section_base_address("libc")
                offset = parse_address(gef.config["gef.main_arena_offset"])
                if libc_base:
                    dbg(f"Using main_arena_offset={offset:#x} from config")
                    addr = libc_base + offset

                    # Verify the found address before returning
                    if GlibcArena.verify(addr):
                        return addr
            except gdb.error:
                pass

        # First, try to find `main_arena` symbol directly
        try:
            return parse_address(f"&{LIBC_HEAP_MAIN_ARENA_DEFAULT_NAME}")
        except gdb.error:
            pass

        # Second, try to find it by offset from `__malloc_hook`
        if gef.libc.version < (2, 34):
            try:
                malloc_hook_addr = parse_address("(void *)&__malloc_hook")

                struct_size = ctypes.sizeof(GlibcArena.malloc_state_t())

                if is_x86():
                    addr = align_address_to_size(malloc_hook_addr + gef.arch.ptrsize, 0x20)
                elif is_arch(Elf.Abi.AARCH64):
                    addr = malloc_hook_addr - gef.arch.ptrsize*2 - struct_size
                elif is_arch(Elf.Abi.ARM):
                    addr = malloc_hook_addr - gef.arch.ptrsize - struct_size
                else:
                    addr = None

                # Verify the found address before returning
                if addr and GlibcArena.verify(addr):
                    return addr

            except gdb.error:
                pass

        # Last resort, try to find it via brute force if enabled in settings
        if gef.config["gef.bruteforce_main_arena"]:
            alignment = 0x8
            try:
                dbg("Trying to bruteforce main_arena address")
                # setup search_range for `main_arena` to `.data` of glibc
                search_filter = lambda f: "libc" in f.filename and f.name == ".data"
                dotdata = list(filter(search_filter, get_info_files()))[0]
                search_range = range(dotdata.zone_start, dotdata.zone_end, alignment)
                # find first possible candidate
                for addr in search_range:
                    if GlibcArena.verify(addr):
                        dbg(f"Found candidate at {addr:#x}")
                        return addr
                dbg("Bruteforce not successful")
            except Exception:
                pass

        # Nothing helped
        err_msg = f"Cannot find main_arena for {gef.arch.arch}. You might want to set a manually found libc offset "
        if not gef.config["gef.bruteforce_main_arena"]:
            err_msg += "or allow bruteforcing "
        err_msg += "through the GEF config."
        raise OSError(err_msg)

    @property
    def selected_arena(self) -> Optional[GlibcArena]:
        if not self.__libc_selected_arena:
            # `selected_arena` must default to `main_arena`
            self.__libc_selected_arena = self.main_arena
        return self.__libc_selected_arena

    @selected_arena.setter
    def selected_arena(self, value: GlibcArena) -> None:
        self.__libc_selected_arena = value
        return

    @property
    def arenas(self) -> Union[List, Iterator[GlibcArena]]:
        if not self.main_arena:
            return []
        return iter(self.main_arena)

    @property
    def base_address(self) -> Optional[int]:
        if not self.__heap_base:
            base = 0
            try:
                base = parse_address("mp_->sbrk_base")
                base = self.malloc_align_address(base)
            except gdb.error:
                # missing symbol, try again
                base = 0
            if not base:
                base = get_section_base_address("[heap]")
            self.__heap_base = base
        return self.__heap_base

    @property
    def chunks(self) -> Union[List, Iterator]:
        if not self.base_address:
            return []
        return iter(GlibcChunk(self.base_address, from_base=True))

    @property
    def min_chunk_size(self) -> int:
        return 4 * gef.arch.ptrsize

    @property
    def malloc_alignment(self) -> int:
        assert gef.libc.version
        __default_malloc_alignment = 0x10
        if gef.libc.version >= (2, 26) and is_x86_32():
            # Special case introduced in Glibc 2.26:
            # https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/i386/malloc-alignment.h#L22
            return __default_malloc_alignment
        # Generic case:
        # https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/generic/malloc-alignment.h#L22
        return 2 * gef.arch.ptrsize

    def csize2tidx(self, size: int) -> int:
        return abs((size - self.min_chunk_size + self.malloc_alignment - 1)) // self.malloc_alignment

    def tidx2size(self, idx: int) -> int:
        return idx * self.malloc_alignment + self.min_chunk_size

    def malloc_align_address(self, address: int) -> int:
        """Align addresses according to glibc's MALLOC_ALIGNMENT. See also Issue #689 on Github"""
        malloc_alignment = self.malloc_alignment
        ceil = lambda n: int(-1 * n // 1 * -1)
        return malloc_alignment * ceil((address / malloc_alignment))


class GefSetting:
    """Basic class for storing gef settings as objects"""

    def __init__(self, value: Any, cls: Optional[type] = None, description: Optional[str] = None, hooks: Optional[Dict[str, Callable]] = None)  -> None:
        self.value = value
        self.type = cls or type(value)
        self.description = description or ""
        self.hooks: Dict[str, List[Callable]] = collections.defaultdict(list)
        if not hooks:
            hooks = {}

        for access, func in hooks.items():
            self.add_hook(access, func)
        return

    def __str__(self) -> str:
        return f"Setting(type={self.type.__name__}, value='{self.value}', desc='{self.description[:10]}...', " \
                f"read_hooks={len(self.hooks['on_read'])}, write_hooks={len(self.hooks['on_write'])})"

    def add_hook(self, access, func):
        if access != "on_read" and access != "on_write":
            raise ValueError("invalid access type")
        if not callable(func):
            raise ValueError("hook is not callable")
        self.hooks[access].append(func)

    @staticmethod
    def no_spaces(value):
        if " " in value:
            raise ValueError("setting cannot contain spaces")


class GefSettingsManager(dict):
    """
    GefSettings acts as a dict where the global settings are stored and can be read, written or deleted as any other dict.
    For instance, to read a specific command setting: `gef.config[mycommand.mysetting]`
    """
    def __getitem__(self, name: str) -> Any:
        setting : GefSetting = super().__getitem__(name)
        self.__invoke_read_hooks(setting)
        return setting.value

    def __setitem__(self, name: str, value: Any) -> None:
        # check if the key exists
        if super().__contains__(name):
            # if so, update its value directly
            setting = super().__getitem__(name)
            if not isinstance(setting, GefSetting): raise ValueError
            setting.value = setting.type(value)
        else:
            # if not, `value` must be a GefSetting
            if not isinstance(value, GefSetting): raise Exception("Invalid argument")
            if not value.type: raise Exception("Invalid type")
            if not value.description: raise Exception("Invalid description")
            setting = value
            value = setting.value
        super().__setitem__(name, setting)
        self.__invoke_write_hooks(setting, value)
        return

    def __delitem__(self, name: str) -> None:
        return super().__delitem__(name)

    def raw_entry(self, name: str) -> GefSetting:
        return super().__getitem__(name)

    def __invoke_read_hooks(self, setting: GefSetting) -> None:
        for callback in setting.hooks["on_read"]:
            callback()
        return

    def __invoke_write_hooks(self, setting: GefSetting, value: Any) -> None:
        for callback in setting.hooks["on_write"]:
            callback(value)
        return


class GefSessionManager(GefManager):
    """Class managing the runtime properties of GEF. """
    def __init__(self) -> None:
        self.reset_caches()
        self.remote: Optional["GefRemoteSessionManager"] = None
        self.remote_initializing: bool = False
        self.qemu_mode: bool = False
        self.convenience_vars_index: int = 0
        self.heap_allocated_chunks: List[Tuple[int, int]] = []
        self.heap_freed_chunks: List[Tuple[int, int]] = []
        self.heap_uaf_watchpoints: List[UafWatchpoint] = []
        self.pie_breakpoints: Dict[int, PieVirtualBreakpoint] = {}
        self.pie_counter: int = 1
        self.aliases: List[GefAlias] = []
        self.modules: List[FileFormat] = []
        self.constants = {} # a dict for runtime constants (like 3rd party file paths)
        for constant in ("python3", "readelf", "file", "ps"):
            self.constants[constant] = which(constant)
        return

    def reset_caches(self) -> None:
        super().reset_caches()
        self._auxiliary_vector = None
        self._pagesize = None
        self._os = None
        self._pid = None
        self._file = None
        self._maps: Optional[pathlib.Path] = None
        self._root: Optional[pathlib.Path] = None
        return

    def __str__(self) -> str:
        return f"Session({'Local' if self.remote is None else 'Remote'}, pid={self.pid or 'Not running'}, os='{self.os}')"

    @property
    def auxiliary_vector(self) -> Optional[Dict[str, int]]:
        if not is_alive():
            return None
        if is_qemu_system():
            return None
        if not self._auxiliary_vector:
            auxiliary_vector = {}
            auxv_info = gdb.execute("info auxv", to_string=True)
            if not auxv_info or "failed" in auxv_info:
                err("Failed to query auxiliary variables")
                return None
            for line in auxv_info.splitlines():
                line = line.split('"')[0].strip()  # remove the ending string (if any)
                line = line.split()  # split the string by whitespace(s)
                if len(line) < 4:
                    continue
                __av_type = line[1]
                __av_value = line[-1]
                auxiliary_vector[__av_type] = int(__av_value, base=0)
            self._auxiliary_vector = auxiliary_vector
        return self._auxiliary_vector

    @property
    def os(self) -> str:
        """Return the current OS."""
        if not self._os:
            self._os = platform.system().lower()
        return self._os

    @property
    def pid(self) -> int:
        """Return the PID of the target process."""
        if not self._pid:
            pid = gdb.selected_inferior().pid if not gef.session.qemu_mode else gdb.selected_thread().ptid[1]
            if not pid:
                raise RuntimeError("cannot retrieve PID for target process")
            self._pid = pid
        return self._pid

    @property
    def file(self) -> Optional[pathlib.Path]:
        """Return a Path object of the target process."""
        if gef.session.remote is not None:
            return gef.session.remote.file
        fpath: str = gdb.current_progspace().filename
        if fpath and not self._file:
            self._file = pathlib.Path(fpath).expanduser()
        return self._file

    @property
    def cwd(self) -> Optional[pathlib.Path]:
        if gef.session.remote is not None:
            return gef.session.remote.root
        return self.file.parent if self.file else None

    @property
    def pagesize(self) -> int:
        """Get the system page size"""
        auxval = self.auxiliary_vector
        if not auxval:
            return DEFAULT_PAGE_SIZE
        self._pagesize = auxval["AT_PAGESZ"]
        return self._pagesize

    @property
    def canary(self) -> Optional[Tuple[int, int]]:
        """Return a tuple of the canary address and value, read from the canonical
        location if supported by the architecture. Otherwise, read from the auxiliary
        vector."""
        try:
            canary_location = gef.arch.canary_address()
            canary = gef.memory.read_integer(canary_location)
        except NotImplementedError:
            # Fall back to `AT_RANDOM`, which is the original source
            # of the canary value but not the canonical location
            return self.original_canary
        return canary, canary_location

    @property
    def original_canary(self) -> Optional[Tuple[int, int]]:
        """Return a tuple of the initial canary address and value, read from the
        auxiliary vector."""
        auxval = self.auxiliary_vector
        if not auxval:
            return None
        canary_location = auxval["AT_RANDOM"]
        canary = gef.memory.read_integer(canary_location)
        canary &= ~0xFF
        return canary, canary_location


    @property
    def maps(self) -> Optional[pathlib.Path]:
        """Returns the Path to the procfs entry for the memory mapping."""
        if not is_alive():
            return None
        if not self._maps:
            if gef.session.remote is not None:
                self._maps = gef.session.remote.maps
            else:
                self._maps = pathlib.Path(f"/proc/{self.pid}/maps")
        return self._maps

    @property
    def root(self) -> Optional[pathlib.Path]:
        """Returns the path to the process's root directory."""
        if not is_alive():
            return None
        if not self._root:
            self._root = pathlib.Path(f"/proc/{self.pid}/root")
        return self._root

class GefRemoteSessionManager(GefSessionManager):
    """Class for managing remote sessions with GEF. It will create a temporary environment
    designed to clone the remote one."""
    def __init__(self, host: str, port: int, pid: int =-1, qemu: Optional[pathlib.Path] = None) -> None:
        super().__init__()
        self.__host = host
        self.__port = port
        self.__local_root_fd = tempfile.TemporaryDirectory()
        self.__local_root_path = pathlib.Path(self.__local_root_fd.name)
        self.__qemu = qemu
        dbg(f"[remote] initializing remote session with {self.target} under {self.root}")
        if not self.connect(pid):
            raise EnvironmentError(f"Cannot connect to remote target {self.target}")
        if not self.setup():
            raise EnvironmentError(f"Failed to create a proper environment for {self.target}")
        return

    def close(self) -> None:
        self.__local_root_fd.cleanup()
        try:
            gef_on_new_unhook(self.remote_objfile_event_handler)
            gef_on_new_hook(new_objfile_handler)
        except Exception as e:
            warn(f"Exception while restoring local context: {str(e)}")
        return

    def in_qemu_user(self) -> bool:
        return self.__qemu is not None

    def __str__(self) -> str:
        return f"RemoteSession(target='{self.target}', local='{self.root}', pid={self.pid}, qemu_user={bool(self.in_qemu_user())})"

    @property
    def target(self) -> str:
        return f"{self.__host}:{self.__port}"

    @property
    def root(self) -> pathlib.Path:
        return self.__local_root_path.absolute()

    @property
    def file(self) -> pathlib.Path:
        """Path to the file being debugged as seen by the remote endpoint."""
        if not self._file:
            filename = gdb.current_progspace().filename
            if not filename:
                raise RuntimeError("No session started")
            start_idx = len("target:") if filename.startswith("target:") else 0
            self._file = pathlib.Path(filename[start_idx:])
        return self._file

    @property
    def lfile(self) -> pathlib.Path:
        """Local path to the file being debugged."""
        return self.root / str(self.file).lstrip("/")

    @property
    def maps(self) -> pathlib.Path:
        if not self._maps:
            self._maps = self.root / f"proc/{self.pid}/maps"
        return self._maps

    def sync(self, src: str, dst: Optional[str] = None) -> bool:
        """Copy the `src` into the temporary chroot. If `dst` is provided, that path will be
        used instead of `src`."""
        if not dst:
            dst = src
        tgt = self.root / dst.lstrip("/")
        if tgt.exists():
            return True
        tgt.parent.mkdir(parents=True, exist_ok=True)
        dbg(f"[remote] downloading '{src}' -> '{tgt}'")
        gdb.execute(f"remote get '{src}' '{tgt.absolute()}'")
        return tgt.exists()

    def connect(self, pid: int) -> bool:
        """Connect to remote target. If in extended mode, also attach to the given PID."""
        # before anything, register our new hook to download files from the remote target
        dbg(f"[remote] Installing new objfile handlers")
        gef_on_new_unhook(new_objfile_handler)
        gef_on_new_hook(self.remote_objfile_event_handler)

        # then attempt to connect
        is_extended_mode = (pid > -1)
        dbg(f"[remote] Enabling extended remote: {bool(is_extended_mode)}")
        try:
            with DisableContextOutputContext():
                cmd = f"target {'extended-' if is_extended_mode else ''}remote {self.target}"
                dbg(f"[remote] Executing '{cmd}'")
                gdb.execute(cmd)
                if is_extended_mode:
                    gdb.execute(f"attach {pid:d}")
            return True
        except Exception as e:
            err(f"Failed to connect to {self.target}: {e}")

        # a failure will trigger the cleanup, deleting our hook anyway
        return False

    def setup(self) -> bool:
        # setup remote adequately depending on remote or qemu mode
        if self.in_qemu_user():
            dbg(f"Setting up as qemu session, target={self.__qemu}")
            self.__setup_qemu()
        else:
            dbg(f"Setting up as remote session")
            self.__setup_remote()

        # refresh gef to consider the binary
        reset_all_caches()
        gef.binary = Elf(self.lfile)
        reset_architecture()
        return True

    def __setup_qemu(self) -> bool:
        # setup emulated file in the chroot
        assert self.__qemu
        target = self.root / str(self.__qemu.parent).lstrip("/")
        target.mkdir(parents=True, exist_ok=False)
        shutil.copy2(self.__qemu, target)
        self._file = self.__qemu
        assert self.lfile.exists()

        # create a procfs
        procfs = self.root / f"proc/{self.pid}/"
        procfs.mkdir(parents=True, exist_ok=True)

        ## /proc/pid/cmdline
        cmdline = procfs / "cmdline"
        if not cmdline.exists():
            with cmdline.open("w") as fd:
                fd.write("")

        ## /proc/pid/environ
        environ = procfs / "environ"
        if not environ.exists():
            with environ.open("wb") as fd:
                fd.write(b"PATH=/bin\x00HOME=/tmp\x00")

        ## /proc/pid/maps
        maps = procfs / "maps"
        if not maps.exists():
            with maps.open("w") as fd:
                fname = self.file.absolute()
                mem_range = "00000000-ffffffff" if is_32bit() else "0000000000000000-ffffffffffffffff"
                fd.write(f"{mem_range} rwxp 00000000 00:00 0                    {fname}\n")
        return True

    def __setup_remote(self) -> bool:
        # get the file
        fpath = f"/proc/{self.pid}/exe"
        if not self.sync(fpath, str(self.file)):
            err(f"'{fpath}' could not be fetched on the remote system.")
            return False

        # pseudo procfs
        for _file in ("maps", "environ", "cmdline"):
            fpath = f"/proc/{self.pid}/{_file}"
            if not self.sync(fpath):
                err(f"'{fpath}' could not be fetched on the remote system.")
                return False

        # makeup a fake mem mapping in case we failed to retrieve it
        maps = self.root / f"proc/{self.pid}/maps"
        if not maps.exists():
            with maps.open("w") as fd:
                fname = self.file.absolute()
                mem_range = "00000000-ffffffff" if is_32bit() else "0000000000000000-ffffffffffffffff"
                fd.write(f"{mem_range} rwxp 00000000 00:00 0                    {fname}\n")
        return True

    def remote_objfile_event_handler(self, evt: "gdb.NewObjFileEvent") -> None:
        dbg(f"[remote] in remote_objfile_handler({evt.new_objfile.filename if evt else 'None'}))")
        if not evt or not evt.new_objfile.filename:
            return
        if not evt.new_objfile.filename.startswith("target:") and not evt.new_objfile.filename.startswith("/"):
            warn(f"[remote] skipping '{evt.new_objfile.filename}'")
            return
        if evt.new_objfile.filename.startswith("target:"):
            src: str = evt.new_objfile.filename[len("target:"):]
            if not self.sync(src):
                raise FileNotFoundError(f"Failed to sync '{src}'")
        return


class GefUiManager(GefManager):
    """Class managing UI settings."""
    def __init__(self) -> None:
        self.redirect_fd : Optional[TextIOWrapper] = None
        self.context_hidden = False
        self.stream_buffer : Optional[StringIO] = None
        self.highlight_table: Dict[str, str] = {}
        self.watches: Dict[int, Tuple[int, str]] = {}
        self.context_messages: List[Tuple[str, str]] = []
        return


class GefLibcManager(GefManager):
    """Class managing everything libc-related (except heap)."""
    def __init__(self) -> None:
        self._version : Optional[Tuple[int, int]] = None
        return

    def __str__(self) -> str:
        return f"Libc(version='{self.version}')"

    @property
    def version(self) -> Optional[Tuple[int, int]]:
        if not is_alive():
            return None
        if not self._version:
            self._version = GefLibcManager.find_libc_version()
        return self._version

    @staticmethod
    @lru_cache()
    def find_libc_version() -> Tuple[int, ...]:
        sections = gef.memory.maps
        for section in sections:
            match = re.search(r"libc6?[-_](\d+)\.(\d+)\.so", section.path)
            if match:
                return tuple(int(_) for _ in match.groups())
            if "libc" in section.path:
                try:
                    with open(section.path, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                match = re.search(PATTERN_LIBC_VERSION, data)
                if match:
                    return tuple(int(_) for _ in match.groups())
        return 0, 0




class Gef:
    """The GEF root class, which serves as a entrypoint for all the debugging session attributes (architecture,
    memory, settings, etc.)."""
    binary: Optional[FileFormat]
    arch: Architecture
    config : GefSettingsManager
    ui: GefUiManager
    libc: GefLibcManager
    memory : GefMemoryManager
    heap : GefHeapManager
    session : GefSessionManager
    gdb: GefCommand

    def __init__(self) -> None:
        self.binary: Optional[FileFormat] = None
        self.arch: Architecture = GenericArchitecture() # see PR #516, will be reset by `new_objfile_handler`
        self.config = GefSettingsManager()
        self.ui = GefUiManager()
        self.libc = GefLibcManager()
        return

    def __str__(self) -> str:
        return f"Gef(binary='{self.binary or 'None'}', arch={self.arch})"

    def reinitialize_managers(self) -> None:
        """Reinitialize the managers. Avoid calling this function directly, using `pi reset()` is preferred"""
        self.memory = GefMemoryManager()
        self.heap = GefHeapManager()
        self.session = GefSessionManager()
        return

    def setup(self) -> None:
        """Setup initialize the runtime setup, which may require for the `gef` to be not None."""
        self.reinitialize_managers()
        self.gdb = GefCommand()
        self.gdb.setup()
        tempdir = self.config["gef.tempdir"]
        gef_makedirs(tempdir)
        gdb.execute(f"save gdb-index '{tempdir}'")
        return

    def reset_caches(self) -> None:
        """Recursively clean the cache of all the managers. Avoid calling this function directly, using `reset-cache`
        is preferred"""
        for mgr in (self.memory, self.heap, self.session, self.arch):
            mgr.reset_caches()
        return


if __name__ == "__main__":
    if sys.version_info[0] == 2:
        err("GEF has dropped Python2 support for GDB when it reached EOL on 2020/01/01.")
        err("If you require GEF for GDB+Python2, use https://github.com/hugsy/gef-legacy.")
        exit(1)

    if GDB_VERSION < GDB_MIN_VERSION or PYTHON_VERSION < PYTHON_MIN_VERSION:
        err("You're using an old version of GDB. GEF will not work correctly. "
            f"Consider updating to GDB {'.'.join(map(str, GDB_MIN_VERSION))} or higher "
            f"(with Python {'.'.join(map(str, PYTHON_MIN_VERSION))} or higher).")
        exit(1)

    try:
        pyenv = which("pyenv")
        PYENV_ROOT = gef_pystring(subprocess.check_output([pyenv, "root"]).strip())
        PYENV_VERSION = gef_pystring(subprocess.check_output([pyenv, "version-name"]).strip())
        site_packages_dir = os.path.join(PYENV_ROOT, "versions", PYENV_VERSION, "lib",
                                             f"python{PYENV_VERSION[:3]}", "site-packages")
        site.addsitedir(site_packages_dir)
    except FileNotFoundError:
        pass

    # When using a Python virtual environment, GDB still loads the system-installed Python
    # so GEF doesn't load site-packages dir from environment
    # In order to fix it, from the shell with venv activated we run the python binary,
    # take and parse its path, add the path to the current python process using sys.path.extend
    PYTHONBIN = which("python3")
    PREFIX = gef_pystring(subprocess.check_output([PYTHONBIN, '-c', 'import os, sys;print((sys.prefix))'])).strip("\\n")
    if PREFIX != sys.base_prefix:
        SITE_PACKAGES_DIRS = subprocess.check_output(
            [PYTHONBIN, "-c", "import os, sys;print(os.linesep.join(sys.path).strip())"]).decode("utf-8").split()
        sys.path.extend(SITE_PACKAGES_DIRS)

    # setup config
    gdb_initial_settings = (
        "set confirm off",
        "set verbose off",
        "set pagination off",
        "set print elements 0",
        "set history save on",
        f"set history filename {os.getenv('GDBHISTFILE', '~/.gdb_history')}",
        "set output-radix 0x10",
        "set print pretty on",
        "set disassembly-flavor intel",
        "handle SIGALRM print nopass",
    )
    for cmd in gdb_initial_settings:
        try:
            gdb.execute(cmd)
        except gdb.error:
            pass

    # load GEF, set up the managers and load the plugins, functions,
    reset()
    gef.gdb.load()
    gef.gdb.show_banner()

    # load config
    gef.gdb.load_extra_plugins()

    # setup gdb prompt
    gdb.prompt_hook = __gef_prompt__

    # gdb events configuration
    gef_on_continue_hook(continue_handler)
    gef_on_stop_hook(hook_stop_handler)
    gef_on_new_hook(new_objfile_handler)
    gef_on_exit_hook(exit_handler)
    gef_on_memchanged_hook(memchanged_handler)
    gef_on_regchanged_hook(regchanged_handler)

    progspace = gdb.current_progspace()
    if progspace and progspace.filename:
        # if here, we are sourcing gef from a gdb session already attached, force call to new_objfile (see issue #278)
        new_objfile_handler(None)

    GefTmuxSetup()

    # `target remote` commands cannot be disabled, so print a warning message instead
    errmsg = "Using `target remote` with GEF does not work, use `gef-remote` instead. You've been warned."
    hook = f"""pi if calling_function() != "connect": err("{errmsg}")"""
    gdb.execute(f"define target hook-remote\n{hook}\nend")
    gdb.execute(f"define target hook-extended-remote\n{hook}\nend")

    # restore saved breakpoints (if any)
    bkp_fpath = pathlib.Path(gef.config["gef.autosave_breakpoints_file"]).expanduser().absolute()
    if bkp_fpath.exists() and bkp_fpath.is_file():
        gdb.execute(f"source {bkp_fpath}")
