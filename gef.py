# -*- coding: utf-8 -*-
#
#
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
# It has full support for both Python2 and Python3 and works on
#   * x86-32 & x86-64
#   * arm v5,v6,v7
#   * aarch64 (armv8)
#   * mips & mips64
#   * powerpc & powerpc64
#   * sparc & sparc64(v9)
#
# Requires GDB 7.x compiled with Python (2.x, or 3.x)
#
# To start: in gdb, type `source /path/to/gef.py`
#
#######################################################################################
#
# gef is distributed under the MIT License (MIT)
# Copyright (c) 2013-2018 crazy rabbidz
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
#
#


from __future__ import print_function, division, absolute_import

import abc
import binascii
import codecs
import collections
import ctypes
import fcntl
import functools
import getopt
import hashlib
import imp
import inspect
import itertools
import os
import platform
import re
import shutil
import socket
import string
import struct
import subprocess
import sys
import tempfile
import termios
import time
import traceback


PYTHON_MAJOR = sys.version_info[0]


if PYTHON_MAJOR == 2:
    from HTMLParser import HTMLParser #pylint: disable=import-error
    from cStringIO import StringIO #pylint: disable=import-error
    from urllib import urlopen #pylint: disable=no-name-in-module
    import ConfigParser as configparser
    import xmlrpclib #pylint: disable=import-error

    # Compat Py2/3 hacks
    def range(*args):
        """Replace range() builtin with an iterator version."""
        if len(args) < 1:
            raise TypeError()
        start, end, step = 0, args[0], 1
        if len(args) == 2: start, end = args
        if len(args) == 3: start, end, step = args
        for n in itertools.count(start=start, step=step):
            if (step>0 and n >= end) or (step<0 and n<=end): break
            yield n

    FileNotFoundError = IOError #pylint: disable=redefined-builtin
    ConnectionRefusedError = socket.error #pylint: disable=redefined-builtin

    LEFT_ARROW = "<-"
    RIGHT_ARROW = "->"
    DOWN_ARROW = "\\->"
    HORIZONTAL_LINE = "-"
    VERTICAL_LINE = "|"
    CROSS = "x"
    TICK = "v"
    GEF_PROMPT = "gef> "
    GEF_PROMPT_ON = "\001\033[1;32m\002{0:s}\001\033[0m\002".format(GEF_PROMPT)
    GEF_PROMPT_OFF = "\001\033[1;31m\002{0:s}\001\033[0m\002".format(GEF_PROMPT)

elif PYTHON_MAJOR == 3:
    from html.parser import HTMLParser
    from io import StringIO
    from urllib.request import urlopen
    import configparser
    import xmlrpc.client as xmlrpclib

    # Compat Py2/3 hack
    long = int #pylint: disable=invalid-name
    unicode = str #pylint: disable=invalid-name

    LEFT_ARROW = " \u2190 "
    RIGHT_ARROW = " \u2192 "
    DOWN_ARROW = "\u21b3"
    HORIZONTAL_LINE = "\u2500"
    VERTICAL_LINE = "\u2502"
    CROSS = "\u2718 "
    TICK = "\u2713 "
    GEF_PROMPT = "gef\u27a4  "
    GEF_PROMPT_ON = "\001\033[1;32m\002{0:s}\001\033[0m\002".format(GEF_PROMPT)
    GEF_PROMPT_OFF = "\001\033[1;31m\002{0:s}\001\033[0m\002".format(GEF_PROMPT)

else:
    raise Exception("WTF is this Python version??")


def http_get(url):
    """Basic HTTP wrapper for GET request. Return the body of the page if HTTP code is OK,
    otherwise return None."""
    try:
        http = urlopen(url)
        if http.getcode() != 200:
            return None
        return http.read()
    except Exception:
        return None


def update_gef(argv):
    """Try to update `gef` to the latest version pushed on GitHub. Return 0 on success,
    1 on failure. """
    gef_local = os.path.realpath(argv[0])
    hash_gef_local = hashlib.sha512(open(gef_local, "rb").read()).digest()
    gef_remote = "https://raw.githubusercontent.com/hugsy/gef/master/gef.py"
    gef_remote_data = http_get(gef_remote)
    if gef_remote_data is None:
        gef_print("[-] Failed to get remote gef")
        return 1

    hash_gef_remote = hashlib.sha512(gef_remote_data).digest()
    if hash_gef_local == hash_gef_remote:
        gef_print("[-] No update")
    else:
        with open(gef_local, "wb") as f:
            f.write(gef_remote_data)
        gef_print("[+] Updated")
    return 0


try:
    import gdb
except ImportError:
    # if out of gdb, the only action allowed is to update gef.py
    if len(sys.argv)==2 and sys.argv[1]=="--update":
        sys.exit( update_gef(sys.argv) )
    gef_print("[-] gef cannot run as standalone")
    sys.exit(0)

__gef__                                = None
__commands__                           = []
__aliases__                            = []
__config__                             = {}
__watches__                            = {}
__infos_files__                        = []
__gef_convenience_vars_index__         = 0
__context_messages__                   = []
__heap_allocated_list__                = []
__heap_freed_list__                    = []
__heap_uaf_watchpoints__               = []
__pie_breakpoints__                    = {}
__pie_counter__                        = 1
__gef_remote__                         = None
__gef_qemu_mode__                      = False
__gef_default_main_arena__             = "main_arena"
__gef_int_stream_buffer__              = None

DEFAULT_PAGE_ALIGN_SHIFT               = 12
DEFAULT_PAGE_SIZE                      = 1 << DEFAULT_PAGE_ALIGN_SHIFT
GEF_RC                                 = os.path.join(os.getenv("HOME"), ".gef.rc")
GEF_TEMP_DIR                           = os.path.join(tempfile.gettempdir(), "gef")
GEF_MAX_STRING_LENGTH                  = 50

GDB_MIN_VERSION                         = (7, 7)
GDB_VERSION_MAJOR, GDB_VERSION_MINOR    = [int(_) for _ in re.search(r"(\d+)[^\d]+(\d+)", gdb.VERSION).groups()]
GDB_VERSION                             = (GDB_VERSION_MAJOR, GDB_VERSION_MINOR)

current_elf  = None
current_arch = None

if PYTHON_MAJOR==3:
    lru_cache = functools.lru_cache
else:
    def lru_cache(maxsize = 128):
        """Portage of the Python3 LRU cache mechanism provided by itertools."""
        class GefLruCache(object):
            """Local LRU cache for Python2"""
            def __init__(self, input_func, max_size):
                self._input_func        = input_func
                self._max_size          = max_size
                self._caches_dict       = {}
                self._caches_info       = {}
                return

            def cache_info(self, caller=None):
                """Return a string with statistics of cache usage."""
                if caller not in self._caches_dict:
                    return ""
                hits = self._caches_info[caller]["hits"]
                missed = self._caches_info[caller]["missed"]
                cursz = len(self._caches_dict[caller])
                return "CacheInfo(hits={}, misses={}, maxsize={}, currsize={})".format(hits, missed, self._max_size, cursz)

            def cache_clear(self, caller=None):
                """Clear a cache."""
                if caller in self._caches_dict:
                    self._caches_dict[caller] = collections.OrderedDict()
                return

            def __get__(self, obj, objtype):
                """Cache getter."""
                return_func = functools.partial(self._cache_wrapper, obj)
                return_func.cache_clear = functools.partial(self.cache_clear, obj)
                return functools.wraps(self._input_func)(return_func)

            def __call__(self, *args, **kwargs):
                """Invoking the wrapped function, by attempting to get its value from cache if existing."""
                return self._cache_wrapper(None, *args, **kwargs)

            __call__.cache_clear = cache_clear
            __call__.cache_info  = cache_info

            def _cache_wrapper(self, caller, *args, **kwargs):
                """Defines the caching mechanism."""
                kwargs_key = "".join(map(lambda x : str(x) + str(type(kwargs[x])) + str(kwargs[x]), sorted(kwargs)))
                key = "".join(map(lambda x : str(type(x)) + str(x) , args)) + kwargs_key
                if caller not in self._caches_dict:
                    self._caches_dict[caller] = collections.OrderedDict()
                    self._caches_info[caller] = {"hits":0, "missed":0}

                cur_caller_cache_dict = self._caches_dict[caller]
                if key in cur_caller_cache_dict:
                    self._caches_info[caller]["hits"] += 1
                    return cur_caller_cache_dict[key]

                self._caches_info[caller]["missed"] += 1
                if self._max_size is not None:
                    if len(cur_caller_cache_dict) >= self._max_size:
                        cur_caller_cache_dict.popitem(False)

                cur_caller_cache_dict[key] = self._input_func(caller, *args, **kwargs) if caller != None else self._input_func(*args, **kwargs)
                return cur_caller_cache_dict[key]

        return lambda input_func: functools.wraps(input_func)(GefLruCache(input_func, maxsize))


def reset_all_caches():
    """Free all caches. If an object is cached, it will have a callable attribute `cache_clear`
    which will be invoked to purge the function cache."""

    for mod in dir(sys.modules["__main__"]):
        obj = getattr(sys.modules["__main__"], mod)
        if hasattr(obj, "cache_clear"):
            obj.cache_clear()
    return


def gef_print(x="", *args, **kwargs):
    """Wrapper around print(), using string buffering feature."""
    if __gef_int_stream_buffer__ and not is_debug():
        return __gef_int_stream_buffer__.write(x + kwargs.get("end", "\n"))
    return print(x, *args, **kwargs)


def bufferize(f):
    """Store in memory the content to be printed for a function, and flush it on function exit."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        global __gef_int_stream_buffer__

        if __gef_int_stream_buffer__:
            f(*args, **kwargs)
            return

        __gef_int_stream_buffer__ = StringIO()
        f(*args, **kwargs)
        sys.stdout.write(__gef_int_stream_buffer__.getvalue())
        sys.stdout.flush()
        __gef_int_stream_buffer__ = None

    return wrapper


class Color:
    """Colorify class."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    @staticmethod
    def redify(msg):       return Color.colorify(msg, attrs="red")
    @staticmethod
    def greenify(msg):     return Color.colorify(msg, attrs="green")
    @staticmethod
    def blueify(msg):      return Color.colorify(msg, attrs="blue")
    @staticmethod
    def yellowify(msg):    return Color.colorify(msg, attrs="yellow")
    @staticmethod
    def grayify(msg):      return Color.colorify(msg, attrs="gray")
    @staticmethod
    def pinkify(msg):      return Color.colorify(msg, attrs="pink")
    @staticmethod
    def boldify(msg):      return Color.colorify(msg, attrs="bold")
    @staticmethod
    def underlinify(msg):  return Color.colorify(msg, attrs="underline")
    @staticmethod
    def highlightify(msg): return Color.colorify(msg, attrs="highlight")
    @staticmethod
    def blinkify(msg):     return Color.colorify(msg, attrs="blink")

    @staticmethod
    def colorify(text, attrs):
        """Color a text following the given attributes."""
        if get_gef_setting("gef.disable_color")==True: return text

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(text)
        if colors["highlight"] in msg :   msg.append(colors["highlight_off"])
        if colors["underline"] in msg :   msg.append(colors["underline_off"])
        if colors["blink"] in msg :       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


class Address:
    """GEF representation of memory addresses."""
    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
        self.section = kwargs.get("section", None)
        self.info = kwargs.get("info", None)
        self.valid = kwargs.get("valid", True)
        return

    def __str__(self):
        value = format_address(self.value)
        code_color = get_gef_setting("theme.address_code")
        stack_color = get_gef_setting("theme.address_stack")
        heap_color = get_gef_setting("theme.address_heap")
        if self.is_in_text_segment():
            return Color.colorify(value, attrs=code_color)
        if self.is_in_heap_segment():
            return Color.colorify(value, attrs=heap_color)
        if self.is_in_stack_segment():
            return Color.colorify(value, attrs=stack_color)
        return value

    def is_in_text_segment(self):
        return (hasattr(self.info, "name") and ".text" in self.info.name) or \
            (hasattr(self.section, "path") and get_filepath() == self.section.path and self.section.is_executable())

    def is_in_stack_segment(self):
        return hasattr(self.section, "path") and "[stack]" == self.section.path

    def is_in_heap_segment(self):
        return hasattr(self.section, "path") and "[heap]" == self.section.path

    def dereference(self):
        addr = align_address(long(self.value))
        derefed = dereference(addr)
        return None if derefed is None else long(derefed)


class Permission:
    """GEF representation of Linux permission."""
    NONE      = 0
    READ      = 1
    WRITE     = 2
    EXECUTE   = 4
    ALL       = READ | WRITE | EXECUTE

    def __init__(self, **kwargs):
        self.value = kwargs.get("value", 0)
        return

    def __or__(self, value):
        return self.value | value

    def __and__(self, value):
        return self.value & value

    def __xor__(self, value):
        return self.value ^ value

    def __eq__(self, value):
        return self.value == value

    def __ne__(self, value):
        return self.value != value

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    @staticmethod
    def from_info_sections(*args):
        perm = Permission()
        for arg in args:
            if "READONLY" in arg:
                perm.value += Permission.READ
            if "DATA" in arg:
                perm.value += Permission.WRITE
            if "CODE" in arg:
                perm.value += Permission.EXECUTE
        return perm

    @staticmethod
    def from_process_maps(perm_str):
        perm = Permission()
        if perm_str[0] == "r":
            perm.value += Permission.READ
        if perm_str[1] == "w":
            perm.value += Permission.WRITE
        if perm_str[2] == "x":
            perm.value += Permission.EXECUTE
        return perm


class Section:
    """GEF representation of process memory sections."""
    page_start      = None
    page_end        = None
    offset          = None
    permission      = None
    inode           = None
    path            = None

    def __init__(self, *args, **kwargs):
        for attr in ["page_start", "page_end", "offset", "permission", "inode", "path", ]:
            value = kwargs.get(attr)
            setattr(self, attr, value)
        return

    def is_readable(self):
        return self.permission.value and self.permission.value&Permission.READ

    def is_writable(self):
        return self.permission.value and self.permission.value&Permission.WRITE

    def is_executable(self):
        return self.permission.value and self.permission.value&Permission.EXECUTE

    @property
    def size(self):
        if self.page_end is None or self.page_start is None:
            return -1
        return self.page_end - self.page_start

    @property
    def realpath(self):
        # when in a `gef-remote` session, realpath returns the path to the binary on the local disk, not remote
        return self.path if __gef_remote__ is None else "/tmp/gef/{:d}/{:s}".format(__gef_remote__, self.path)


class Zone:
    name              = None
    zone_start        = None
    zone_end          = None
    filename          = None


class Elf:
    """ Basic ELF parsing.
    Ref:
    - http://www.skyfree.org/linux/references/ELF_Format.pdf
    - http://refspecs.freestandards.org/elf/elfspec_ppc.pdf
    - http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html
    """
    BIG_ENDIAN        = 0
    LITTLE_ENDIAN     = 1

    ELF_32_BITS       = 0x01
    ELF_64_BITS       = 0x02

    X86_64            = 0x3e
    X86_32            = 0x03
    ARM               = 0x28
    MIPS              = 0x08
    POWERPC           = 0x14
    POWERPC64         = 0x15
    SPARC             = 0x02
    SPARC64           = 0x2b
    AARCH64           = 0xb7

    ET_EXEC           = 2
    ET_DYN            = 3
    ET_CORE           = 4


    e_magic           = b'\x7fELF'
    e_class           = ELF_32_BITS
    e_endianness      = LITTLE_ENDIAN
    e_eiversion       = None
    e_osabi           = None
    e_abiversion      = None
    e_pad             = None
    e_type            = ET_EXEC
    e_machine         = X86_32
    e_version         = None
    e_entry           = 0x00
    e_phoff           = None
    e_shoff           = None
    e_flags           = None
    e_ehsize          = None
    e_phentsize       = None
    e_phnum           = None
    e_shentsize       = None
    e_shnum           = None
    e_shstrndx        = None



    def __init__(self, elf="", minimalist=False):
        """Instanciates an Elf object. The default behavior is to create the object by parsing the ELF file on FS.
        But on some cases (QEMU-stub), we may just want a simply minimal object with default values."""
        if minimalist:
            return

        if not os.access(elf, os.R_OK):
            err("'{0}' not found/readable".format(elf))
            err("Failed to get file debug information, most of gef features will not work")
            return

        with open(elf, "rb") as fd:
            # off 0x0
            self.e_magic, self.e_class, self.e_endianness, self.e_eiversion = struct.unpack(">IBBB", fd.read(7))

            # adjust endianness in bin reading
            endian = "<" if self.e_endianness == Elf.LITTLE_ENDIAN else ">"

            # off 0x7
            self.e_osabi, self.e_abiversion = struct.unpack("{}BB".format(endian), fd.read(2))
            # off 0x9
            self.e_pad = fd.read(7)
            # off 0x10
            self.e_type, self.e_machine, self.e_version = struct.unpack("{}HHI".format(endian), fd.read(8))
            # off 0x18
            if self.e_class == Elf.ELF_64_BITS:
                # if arch 64bits
                self.e_entry, self.e_phoff, self.e_shoff = struct.unpack("{}QQQ".format(endian), fd.read(24))
            else:
                # else arch 32bits
                self.e_entry, self.e_phoff, self.e_shoff = struct.unpack("{}III".format(endian), fd.read(12))

            self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum = struct.unpack("{}HHHH".format(endian), fd.read(8))
            self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack("{}HHH".format(endian), fd.read(6))
        return



class Instruction:
    """GEF representation of instruction."""
    def __init__(self, address, location, mnemo, operands):
        self.address, self.location, self.mnemonic, self.operands = address, location, mnemo, operands
        return

    def __str__(self):
        return "{:#10x} {:16} {:6} {:s}".format(self.address,
                                                self.location,
                                                self.mnemonic,
                                                ", ".join(self.operands))

    def is_valid(self):
        return "(bad)" not in self.mnemonic



class GlibcArena:
    """Glibc arena class
    Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671 """
    def __init__(self, addr, name=__gef_default_main_arena__):
        arena = gdb.parse_and_eval(addr)
        malloc_state_t = cached_lookup_type("struct malloc_state")
        self.__name = name
        self.__arena = arena.cast(malloc_state_t)
        self.__addr = long(arena.address)
        return

    def __getitem__(self, item):
        return self.__arena[item]

    def __getattr__(self, item):
        return self.__arena[item]

    def __int__(self):
        return self.__addr

    def fastbin(self, i):
        addr = dereference_as_long(self.fastbinsY[i])
        if addr == 0:
            return None
        return GlibcChunk(addr + 2 * current_arch.ptrsize)

    def bin(self, i):
        idx = i * 2
        fd = dereference_as_long(self.bins[idx])
        bw = dereference_as_long(self.bins[idx + 1])
        return fd, bw

    def get_next(self):
        addr_next = dereference_as_long(self.next)
        arena_main = GlibcArena(self.__name)
        if addr_next == arena_main.__addr:
            return None
        return GlibcArena("*{:#x} ".format(addr_next))

    def __str__(self):
        top             = dereference_as_long(self.top)
        last_remainder  = dereference_as_long(self.last_remainder)
        n               = dereference_as_long(self.next)
        nfree           = dereference_as_long(self.next_free)
        sysmem          = long(self.system_mem)
        fmt = "Arena (base={:#x}, top={:#x}, last_remainder={:#x}, next={:#x}, next_free={:#x}, system_mem={:#x})"
        return fmt.format(self.__addr, top, last_remainder, n, nfree, sysmem)


class GlibcChunk:
    """Glibc chunk class.
    Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/"""

    def __init__(self, addr, from_base=False):
        self.ptrsize = current_arch.ptrsize
        if from_base:
            self.chunk_base_address = addr
            self.address = addr + 2 * self.ptrsize
        else:
            self.chunk_base_address = int(addr - 2 * self.ptrsize)
            self.address = addr

        self.size_addr  = int(self.address - self.ptrsize)
        self.prev_size_addr = self.chunk_base_address
        return

    def get_chunk_size(self):
        return read_int_from_memory(self.size_addr) & (~0x03)

    @property
    def size(self):
        return self.get_chunk_size()

    def get_usable_size(self):
        # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4537
        cursz = self.get_chunk_size()
        if cursz == 0: return cursz
        if self.has_m_bit(): return cursz - 2 * self.ptrsize
        return cursz - self.ptrsize

    @property
    def usable_size(self):
        return self.get_usable_size()

    def get_prev_chunk_size(self):
        return read_int_from_memory(self.prev_size_addr)

    def get_next_chunk(self):
        addr = self.address + self.get_chunk_size()
        return GlibcChunk(addr)

    # if free-ed functions
    def get_fwd_ptr(self):
        return read_int_from_memory(self.address)

    @property
    def fwd(self):
        return self.get_fwd_ptr()

    fd = fwd # for compat

    def get_bkw_ptr(self):
        return read_int_from_memory(self.address + self.ptrsize)

    @property
    def bck(self):
        return self.get_bkw_ptr()

    bk = bck # for compat
    # endif free-ed functions

    def has_p_bit(self):
        """Check for in PREV_INUSE bit
        Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1267"""
        return read_int_from_memory(self.size_addr) & 0x01

    def has_m_bit(self):
        """Check for in IS_MMAPPED bit
        Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1274"""
        return read_int_from_memory(self.size_addr) & 0x02

    def has_n_bit(self):
        """Check for in NON_MAIN_ARENA bit.
        Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1283"""
        return read_int_from_memory(self.size_addr) & 0x04

    def is_used(self):
        """Check if the current block is used by:
        - checking the M bit is true
        - or checking that next chunk PREV_INUSE flag is true """
        if self.has_m_bit():
            return True

        next_chunk = self.get_next_chunk()
        return True if next_chunk.has_p_bit() else False

    def str_chunk_size_flag(self):
        msg = []
        msg.append("PREV_INUSE flag: {}".format(Color.greenify("On") if self.has_p_bit() else Color.redify("Off")))
        msg.append("IS_MMAPPED flag: {}".format(Color.greenify("On") if self.has_m_bit() else Color.redify("Off")))
        msg.append("NON_MAIN_ARENA flag: {}".format(Color.greenify("On") if self.has_n_bit() else Color.redify("Off")))
        return "\n".join(msg)

    def _str_sizes(self):
        msg = []
        failed = False

        try:
            msg.append("Chunk size: {0:d} ({0:#x})".format(self.get_chunk_size()))
            msg.append("Usable size: {0:d} ({0:#x})".format(self.get_usable_size()))
            failed = True
        except gdb.MemoryError:
            msg.append("Chunk size: Cannot read at {:#x} (corrupted?)".format(self.size_addr))

        try:
            msg.append("Previous chunk size: {0:d} ({0:#x})".format(self.get_prev_chunk_size()))
            failed = True
        except gdb.MemoryError:
            msg.append("Previous chunk size: Cannot read at {:#x} (corrupted?)".format(self.chunk_base_address))

        if failed:
            msg.append(self.str_chunk_size_flag())

        return "\n".join(msg)

    def _str_pointers(self):
        fwd = self.address
        bkw = self.address + self.ptrsize

        msg = []
        try:
            msg.append("Forward pointer: {0:#x}".format(self.get_fwd_ptr()))
        except gdb.MemoryError:
            msg.append("Forward pointer: {0:#x} (corrupted?)".format(fwd))

        try:
            msg.append("Backward pointer: {0:#x}".format(self.get_bkw_ptr()))
        except gdb.MemoryError:
            msg.append("Backward pointer: {0:#x} (corrupted?)".format(bkw))

        return "\n".join(msg)

    def str_as_alloced(self):
        return self._str_sizes()

    def str_as_freed(self):
        return "{}\n\n{}".format(self._str_sizes(), self._str_pointers())

    def flags_as_string(self):
        flags = []
        if self.has_p_bit():
            flags.append(Color.colorify("PREV_INUSE", attrs="red bold"))
        if self.has_m_bit():
            flags.append(Color.colorify("IS_MMAPPED", attrs="red bold"))
        if self.has_n_bit():
            flags.append(Color.colorify("NON_MAIN_ARENA", attrs="red bold"))
        return "|".join(flags)

    def __str__(self):
        msg = "{:s}(addr={:#x}, size={:#x}, flags={:s})".format(Color.colorify("Chunk", attrs="yellow bold underline"),
                                                                long(self.address),self.get_chunk_size(), self.flags_as_string())
        return msg

    def pprint(self):
        msg = []
        msg.append(str(self))
        if self.is_used():
            msg.append(self.str_as_alloced())
        else:
            msg.append(self.str_as_freed())

        gdb.write("\n".join(msg) + "\n")
        gdb.flush()
        return


@lru_cache()
def get_main_arena():
    try:
        return GlibcArena(__gef_default_main_arena__)
    except Exception as e:
        err("Failed to get the main arena, heap commands may not work properly: {}".format(e))
        return None


def titlify(text, color=None, msg_color=None):
    """Print a title."""
    cols = get_terminal_size()[1]
    nb = (cols - len(text) - 4)//2
    if color is None:
        color = __config__.get("theme.default_title_line")[0]
    if msg_color is None:
        msg_color = __config__.get("theme.default_title_message")[0]

    msg = []
    msg.append(Color.colorify(HORIZONTAL_LINE * nb + '[ ', attrs=color))
    msg.append(Color.colorify(text, attrs=msg_color))
    msg.append(Color.colorify(' ]' + HORIZONTAL_LINE * nb, attrs=color))
    return "".join(msg)


def _xlog(text, stream, cr=True):
    """Logging core function."""
    text += "\n" if cr else ""
    gdb.write(text, stream)
    if cr:
        gdb.flush()
    return 0


def err(msg, cr=True):   return _xlog("{} {}".format(Color.colorify("[!]", attrs="bold red"), msg), gdb.STDERR, cr)
def warn(msg, cr=True):  return _xlog("{} {}".format(Color.colorify("[*]", attrs="bold yellow"), msg), gdb.STDLOG, cr)
def ok(msg, cr=True):    return _xlog("{} {}".format(Color.colorify("[+]", attrs="bold green"), msg), gdb.STDLOG, cr)
def info(msg, cr=True):  return _xlog("{} {}".format(Color.colorify("[+]", attrs="bold blue"), msg), gdb.STDLOG, cr)


def push_context_message(level, message):
    """Push the message to be displayed the next time the context is invoked."""
    global __context_messages__
    if level not in ("error", "warn", "ok", "info"):
        err("Invalid level '{}', discarding message".format(level))
        return
    __context_messages__.append((level, message))
    return


def show_last_exception():
    """Display the last Python exception."""

    def _show_code_line(fname, idx):
        fname = os.path.expanduser( os.path.expandvars(fname) )
        __data = open(fname, "r").read().splitlines()
        return __data[idx-1] if idx < len(__data) else ""

    gef_print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    gef_print(" Exception raised ".center(80, HORIZONTAL_LINE))
    gef_print("{}: {}".format(Color.colorify(exc_type.__name__, attrs="bold underline red"), exc_value))
    gef_print(" Detailed stacktrace ".center(80, HORIZONTAL_LINE))
    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        filename, lineno, method, code = fs

        if not code or not code.strip():
            code = _show_code_line(filename, lineno)

        gef_print("""{} File "{}", line {:d}, in {}()""".format(DOWN_ARROW, Color.yellowify(filename),
                                                                lineno, Color.greenify(method)))
        gef_print("   {}    {}".format(RIGHT_ARROW, code))

    gef_print(" Last 10 GDB commands ".center(80, HORIZONTAL_LINE))
    gdb.execute("show commands")
    gef_print(" Runtime environment ".center(80, HORIZONTAL_LINE))
    gef_print("* GDB: {}".format(gdb.VERSION))
    gef_print("* Python: {:d}.{:d}.{:d} - {:s}".format(sys.version_info.major, sys.version_info.minor,
                                                       sys.version_info.micro, sys.version_info.releaselevel))
    gef_print("* OS: {:s} - {:s} ({:s}) on {:s}".format(platform.system(), platform.release(),
                                                        platform.architecture()[0],
                                                        " ".join(platform.dist())))
    gef_print(HORIZONTAL_LINE*80)
    gef_print("")
    return


def gef_pystring(x):
    """Python 2 & 3 compatibility function for strings handling."""
    res = str(x, encoding="utf-8") if PYTHON_MAJOR == 3 else x
    substs = [('\n','\\n'), ('\r','\\r'), ('\t','\\t'), ('\v','\\v'), ('\b','\\b'), ]
    for x,y in substs: res = res.replace(x,y)
    return res


def gef_pybytes(x):
    """Python 2 & 3 compatibility function for bytes handling."""
    return bytes(str(x), encoding="utf-8") if PYTHON_MAJOR == 3 else x


@lru_cache()
def which(program):
    """Locate a command on FS."""
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath = os.path.split(program)[0]
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    raise FileNotFoundError("Missing file `{:s}`".format(program))


def hexdump(source, length=0x10, separator=".", show_raw=False, base=0x00):
    """Return the hexdump of `src` argument.
    @param source *MUST* be of type bytes or bytearray
    @param length is the length of items per line
    @param separator is the default character to use if one byte is not printable
    @param show_raw if True, do not add the line nor the text translation
    @param base is the start address of the block being hexdump
    @param func is the function to use to parse bytes (int for Py3, chr for Py2)
    @return a string with the hexdump """
    result = []
    align = get_memory_alignment()*2+2 if is_alive() else 18

    for i in range(0, len(source), length):
        chunk = bytearray(source[i:i + length])
        hexa = " ".join(["{:02x}".format(b) for b in chunk])

        if show_raw:
            result.append(hexa)
            continue

        text = "".join([chr(b) if 0x20 <= b < 0x7F else separator for b in chunk])
        sym = gdb_get_location_from_symbol(base+i)
        sym = "<{:s}+{:04x}>".format(*sym) if sym else ''

        result.append("{addr:#0{aw}x} {sym}    {data:<{dw}}    {text}".format(aw=align,
                                                                              addr=base+i,
                                                                              sym=sym,
                                                                              dw=3*length,
                                                                              data=hexa,
                                                                              text=text))
    return "\n".join(result)


def is_debug():
    """Checks if debug mode is enabled."""
    return get_gef_setting("gef.debug") == True

def disable_context(): set_gef_setting("context.enable", False)
def enable_context(): set_gef_setting("context.enable", True)

def enable_redirect_output(to_file="/dev/null"):
    """Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`."""
    gdb.execute("set logging overwrite")
    gdb.execute("set logging file {:s}".format(to_file))
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")
    return


def disable_redirect_output():
    """Disable the output redirection, if any."""
    gdb.execute("set logging redirect off")
    gdb.execute("set logging off")
    return


def get_gef_setting(name):
    """Read global gef settings. Return None if not found. A valid config setting can never return None,
    but False, 0 or "". So using None as a retval on error is fine."""
    global __config__
    setting = __config__.get(name, None)
    if not setting:
        return None
    return setting[0]


def set_gef_setting(name, value, _type=None, _desc=None):
    """Set global gef settings. Raise ValueError if `name` doesn't exist and `type` and `desc`
    are not provided."""
    global __config__

    if name not in __config__:
        # create new setting
        if _type is None or _desc is None:
            raise ValueError("Setting '{}' is undefined, need to provide type and description".format(name))
        __config__[name] = [_type(value), _type, _desc]
        return

    # set existing setting
    func = __config__[name][1]
    __config__[name][0] = func(value)
    return


def gef_makedirs(path, mode=0o755):
    """Recursive mkdir() creation. If successful, return the absolute path of the directory created."""
    abspath = os.path.realpath(path)
    if os.path.isdir(abspath):
        return abspath

    if PYTHON_MAJOR == 3:
        os.makedirs(path, mode=mode, exist_ok=True)
    else:
        try:
            os.makedirs(path, mode=mode)
        except os.error:
            pass
    return abspath


@lru_cache()
def gdb_lookup_symbol(sym):
    """Fetch the proper symbol or none is not defined."""
    try:
        return gdb.decode_line(sym)[1]
    except gdb.error:
        return None


@lru_cache(maxsize=512)
def gdb_get_location_from_symbol(address):
    """Retrieve the location of the `address` argument from the symbol table.
    Return a tuple with the name and offset if found, None otherwise."""
    # this is horrible, ugly hack and shitty perf...
    # find a *clean* way to get gdb.Location from an address
    name = None
    sym = gdb.execute("info symbol {:#x}".format(address), to_string=True)
    if sym.startswith("No symbol matches"):
        return None

    i = sym.find(" in section ")
    sym = sym[:i].split()
    name, offset = sym[0], 0
    if len(sym) == 3 and sym[2].isdigit():
        offset = int(sym[2])
    return name, offset


def gdb_disassemble(start_pc, **kwargs):
    """Disassemble instructions from `start_pc` (Integer). Accepts the following named parameters:
    - `end_pc` (Integer) only instructions whose start address fall in the interval from start_pc to end_pc are returned.
    - `count` (Integer) list at most this many disassembled instructions
    If `end_pc` and `count` are not provided, the function will behave as if `count=1`.
    Return an iterator of Instruction objects
    """
    frame = gdb.selected_frame()
    arch = frame.architecture()

    for insn in arch.disassemble(start_pc, **kwargs):
        address = insn["addr"]
        asm = insn["asm"].rstrip().split(None, 1)
        if len(asm) > 1:
            mnemo, operands = asm
            operands = operands.split(",")
        else:
            mnemo, operands = asm[0], []

        loc = gdb_get_location_from_symbol(address)
        location = "<{}+{}>".format(*loc) if loc else ""

        yield Instruction(address, location, mnemo, operands)


def gdb_get_nth_previous_instruction_address(addr, n):
    """Return the address (Integer) of the `n`-th instruction before `addr`."""
    # fixed-length ABI
    if current_arch.instruction_length:
        return addr - n*current_arch.instruction_length

    # variable-length ABI
    cur_insn_addr = gef_current_instruction(addr).address

    # we try to find a good set of previous instructions by "guessing" disassembling backwards
    # the 15 comes from the longest instruction valid size
    for i in range(15*n, 0, -1):
        try:
            insns = list(gdb_disassemble(addr-i, end_pc=cur_insn_addr, count=n+1))
        except gdb.MemoryError:
            # this is because we can hit an unmapped page trying to read backward
            break

        # 1. check that the disassembled instructions list size is correct
        if len(insns)!=n+1: # we expect the current instruction plus the n before it
            continue

        # 2. check all instructions are valid
        for insn in insns:
            if not insn.is_valid():
                continue

        # 3. if cur_insn is at the end of the set
        if insns[-1].address==cur_insn_addr:
            return insns[0].address

    return -1


def gdb_get_nth_next_instruction_address(addr, n):
    """Return the address (Integer) of the `n`-th instruction after `addr`."""
    # fixed-length ABI
    if current_arch.instruction_length:
        return addr + n*current_arch.instruction_length

    # variable-length ABI
    insn = list(gdb_disassemble(addr, count=n))[-1]
    return insn.address


def gef_instruction_n(addr, n):
    """Return the `n`-th instruction after `addr` as an Instruction object."""
    return list(gdb_disassemble(addr, count=n+1))[n]


def gef_get_instruction_at(addr):
    """Return the full Instruction found at the specified address."""
    insn = next(gef_disassemble(addr, 1))
    return insn


def gef_current_instruction(addr):
    """Return the current instruction as an Instruction object."""
    return gef_instruction_n(addr, 0)


def gef_next_instruction(addr):
    """Return the next instruction as an Instruction object."""
    return gef_instruction_n(addr, 1)


def gef_disassemble(addr, nb_insn, nb_prev=0):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`.
    Return an iterator of Instruction objects."""
    count = nb_insn + 1 if nb_insn & 1 else nb_insn

    if nb_prev > 0:
        start_addr = gdb_get_nth_previous_instruction_address(addr, nb_prev)
        if start_addr > 0:
            for insn in gdb_disassemble(start_addr, count=nb_prev):
                if insn.address == addr: break
                yield insn

    for insn in gdb_disassemble(addr, count=count):
        yield insn


def capstone_disassemble(location, nb_insn, **kwargs):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before
    `addr` using the Capstone-Engine disassembler, if available.
    Return an iterator of Instruction objects."""

    def cs_insn_to_gef_insn(cs_insn):
        sym_info = gdb_get_location_from_symbol(cs_insn.address)
        loc = "<{}+{}>".format(*sym_info) if sym_info else ""
        ops = [] + cs_insn.op_str.split(', ')
        return Instruction(cs_insn.address, loc, cs_insn.mnemonic, ops)

    capstone    = sys.modules["capstone"]
    arch, mode  = get_capstone_arch(arch=kwargs.get("arch", None), mode=kwargs.get("mode", None), endian=kwargs.get("endian", None))
    cs          = capstone.Cs(arch, mode)
    cs.detail   = True

    page_start  = align_address_to_page(location)
    offset      = location - page_start
    pc          = current_arch.pc

    nb_prev    = int(kwargs.get("nb_prev", 0))
    if nb_prev > 0:
        location = gdb_get_nth_previous_instruction_address(pc, nb_prev)
        nb_insn += nb_prev

    code = kwargs.get("code", read_memory(location, gef_getpagesize() - offset - 1))
    code = bytes(code)

    for insn in cs.disasm(code, location):
        nb_insn -= 1
        yield cs_insn_to_gef_insn(insn)
        if nb_insn==0:
            break
    return


def gef_execute_external(command, as_list=False, *args, **kwargs):
    """Executes an external command and retrieves the result."""
    res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=kwargs.get("shell", False))
    return [gef_pystring(_) for _ in res.splitlines()] if as_list else gef_pystring(res)


def gef_execute_gdb_script(commands):
    """Executes the parameter `source` as GDB command. This is done by writing `commands` to
    a temporary file, which is then executed via GDB `source` command. The tempfile is then deleted."""
    fd, fname = tempfile.mkstemp(suffix=".gdb", prefix="gef_")
    with os.fdopen(fd, "w") as f:
        f.write(commands)
        f.flush()
    if os.access(fname, os.R_OK):
        gdb.execute("source {:s}".format(fname))
        os.unlink(fname)
    return


@lru_cache(32)
def checksec(filename):
    """Check the security property of the ELF binary. The following properties are:
    - Canary
    - NX
    - PIE
    - Fortify
    - Partial/Full RelRO.
    Return a dict() with the different keys mentioned above, and the boolean
    associated whether the protection was found."""

    try:
        readelf = which("readelf")
    except IOError:
        err("Missing `readelf`")
        return

    def __check_security_property(opt, filename, pattern):
        cmd   = [readelf,]
        cmd  += opt.split()
        cmd  += [filename,]
        lines = gef_execute_external(cmd, as_list=True)
        for line in lines:
            if re.search(pattern, line):
                return True
        return False

    results = collections.OrderedDict()
    results["Canary"] = __check_security_property("-s", filename, r"__stack_chk_fail") is True
    has_gnu_stack = __check_security_property("-W -l", filename, r"GNU_STACK") is True
    if has_gnu_stack:
        results["NX"] = __check_security_property("-W -l", filename, r"GNU_STACK.*RWE") is False
    else:
        results["NX"] = False
    results["PIE"] = __check_security_property("-h", filename, r"Type:.*EXEC") is False
    results["Fortify"] = __check_security_property("-s", filename, r"_chk@GLIBC") is True
    results["Partial RelRO"] = __check_security_property("-l", filename, r"GNU_RELRO") is True
    results["Full RelRO"] = __check_security_property("-d", filename, r"BIND_NOW") is True
    return results


@lru_cache()
def get_arch():
    """Return the binary's architecture."""
    if is_alive():
        arch = gdb.selected_frame().architecture()
        return arch.name()

    arch_str = gdb.execute("show architecture", to_string=True).strip()
    if "The target architecture is set automatically (currently " in arch_str:
        # architecture can be auto detected
        arch_str = arch_str.split("(currently ", 1)[1]
        arch_str = arch_str.split(")", 1)[0]
    elif "The target architecture is assumed to be " in arch_str:
        # architecture can be assumed
        arch_str = arch_str.replace("The target architecture is assumed to be ", "")
    else:
        # unknown, we throw an exception to be safe
        raise RuntimeError("Unknown architecture: {}".format(arch_str))
    return arch_str


@lru_cache()
def get_endian():
    """Return the binary endianness."""
    if is_alive():
        return get_elf_headers().e_endianness
    if gdb.execute("show endian", to_string=True).strip().split()[7] == "little" :
        return Elf.LITTLE_ENDIAN
    raise EnvironmentError("Invalid endianess")


def is_big_endian():     return get_endian() == Elf.BIG_ENDIAN
def is_little_endian():  return not is_big_endian()


def flags_to_human(reg_value, value_table):
    """Return a human readable string showing the flag states."""
    flags = []
    for i in value_table:
        flag_str = Color.boldify(value_table[i].upper()) if reg_value & (1<<i) else value_table[i].lower()
        flags.append(flag_str)
    return "[{}]".format(" ".join(flags))


class Architecture(object):
    """Generic metaclass for the architecture supported by GEF."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def all_registers(self):                       pass
    @abc.abstractproperty
    def instruction_length(self):                  pass
    @abc.abstractproperty
    def nop_insn(self):                            pass
    @abc.abstractproperty
    def return_register(self):                     pass
    @abc.abstractproperty
    def flag_register(self):                       pass
    @abc.abstractproperty
    def flags_table(self):                         pass
    @abc.abstractproperty
    def function_parameters(self):                 pass
    @abc.abstractmethod
    def flag_register_to_human(self, val=None):    pass
    @abc.abstractmethod
    def is_call(self, insn):                       pass
    @abc.abstractmethod
    def is_ret(self, insn):                        pass
    @abc.abstractmethod
    def is_conditional_branch(self, insn):         pass
    @abc.abstractmethod
    def is_branch_taken(self, insn):               pass
    @abc.abstractmethod
    def get_ra(self, insn, frame):                 pass

    @property
    def pc(self):
        return get_register("$pc")

    @property
    def sp(self):
        return get_register("$sp")

    @property
    def fp(self):
        return get_register("$fp")

    @property
    def ptrsize(self):
        return get_memory_alignment()

    @property
    def all_registers_stripped(self):
        return [x.strip() for x in self.all_registers]


class ARM(Architecture):
    arch = "ARM"
    mode = "ARM"

    all_registers = ["$r0   ", "$r1   ", "$r2   ", "$r3   ", "$r4   ", "$r5   ", "$r6   ",
                     "$r7   ", "$r8   ", "$r9   ", "$r10  ", "$r11  ", "$r12  ", "$sp   ",
                     "$lr   ", "$pc   ", "$cpsr ",]

    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0041c/Caccegih.html
    # return b"\x00\x00\xa0\xe1" # mov r0,r0
    nop_insn = b"\x01\x10\xa0\xe1" # mov r1,r1
    return_register = "$r0"
    flag_register = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast",
        5: "thumb"
    }
    function_parameters = ["$r0", "$r1", "$r2", "$r3"]
    syscall_register = "$r7"
    syscall_instructions = ["swi 0x0", "swi NR"]

    @property
    def instruction_length(self):
        # Thumb instructions have variable-length (2 or 4-byte)
        return None if is_arm_thumb() else 4

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blx"}
        return mnemo in call_mnemos

    def is_ret(self, insn):
        pop_mnemos = {"pop"}
        branch_mnemos = {"bl", "bx"}
        write_mnemos = {"ldr", "add"}
        if insn.mnemonic in pop_mnemos:
            return insn.operands[-1] == " pc}"
        if insn.mnemonic in branch_mnemos:
            return insn.operands[-1] == "lr"
        if insn.mnemonic in write_mnemos:
            return insn.operands[0] == "pc"
        return

    def flag_register_to_human(self, val=None):
        # http://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
        if val is None:
            reg = self.flag_register
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_conditional_branch(self, insn):
        branch_mnemos = {"beq", "bne", "bleq", "blt", "bgt", "bgez", "bvs", "bvc",
                         "jeq", "jne", "jleq", "jlt", "jgt", "jgez", "jvs", "jvc"}
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        # ref: http://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""

        if mnemo.endswith("eq"): taken, reason = val&(1<<flags["zero"]), "Z"
        elif mnemo.endswith("ne"): taken, reason = val&(1<<flags["zero"]) == 0, "!Z"
        elif mnemo.endswith("lt"): taken, reason = val&(1<<flags["negative"])!=val&(1<<flags["overflow"]), "N!=O"
        elif mnemo.endswith("le"): taken, reason = val&(1<<flags["zero"]) or val&(1<<flags["negative"])!=val&(1<<flags["overflow"]), "Z || N!=O"
        elif mnemo.endswith("gt"): taken, reason = val&(1<<flags["zero"]) == 0 and val&(1<<flags["negative"]) == val&(1<<flags["overflow"]), "!Z && N==O"
        elif mnemo.endswith("ge"): taken, reason = val&(1<<flags["negative"]) == val&(1<<flags["overflow"]), "N==O"
        elif mnemo.endswith("bvs"): taken, reason = val&(1<<flags["overflow"]), "O"
        elif mnemo.endswith("bvc"): taken, reason = val&(1<<flags["overflow"]) == 0, "!O"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            # If it's a pop, we have to peek into the stack, otherwise use lr
            if insn.mnemonic == "pop":
                ra_addr = current_arch.sp + (len(insn.operands)-1) * get_memory_alignment()
                ra = to_unsigned_long(dereference(ra_addr))
            elif insn.mnemonic == "ldr":
                return to_unsigned_long(dereference(current_arch.sp))
            else: # 'bx lr' or 'add pc, lr, #0'
                return get_register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 125
        insns = [
            "push {r0-r2, r7}",
            "mov r0, {:d}".format(addr),
            "mov r1, {:d}".format(size),
            "mov r2, {:d}".format(perm),
            "mov r7, {:d}".format(_NR_mprotect),
            "svc 0",
            "pop {r0-r2, r7}",]
        return "; ".join(insns)


class AARCH64(ARM):
    arch = "ARM64"
    mode = "ARM"

    all_registers = [
        "$x0       ", "$x1       ", "$x2       ", "$x3       ", "$x4       ", "$x5       ", "$x6       ", "$x7       ",
        "$x8       ", "$x9       ", "$x10      ", "$x11      ", "$x12      ", "$x13      ", "$x14      ", "$x15      ",
        "$x16      ", "$x17      ", "$x18      ", "$x19      ", "$x20      ", "$x21      ", "$x22      ", "$x23      ",
        "$x24      ", "$x25      ", "$x26      ", "$x27      ", "$x28      ", "$x29      ", "$x30      ", "$sp       ",
        "$pc       ", "$cpsr     ", "$fpsr     ", "$fpcr     ",]
    return_register = "$x0"
    flag_register = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast"
    }
    function_parameters = ["$x0", "$x1", "$x2", "$x3"]
    syscall_register = "$x8"
    syscall_instructions = ["svc $x0"]

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blr"}
        return mnemo in call_mnemos

    def flag_register_to_human(self, val=None):
        # http://events.linuxfoundation.org/sites/events/files/slides/KoreaLinuxForum-2014.pdf
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        raise OSError("Architecture {:s} not supported yet".format(cls.arch))

    def is_conditional_branch(self, insn):
        # https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf
        # sect. 5.1.1
        mnemo = insn.mnemonic
        branch_mnemos = {"cbnz", "cbz", "tbnz", "tbz"}
        return mnemo.startswith("b.") or mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, operands = insn.mnemonic, insn.operands
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""

        if mnemo in {"cbnz", "cbz", "tbnz", "tbz"}:
            reg = operands[0]
            op = get_register(reg)
            if mnemo=="cbnz":
                if op!=0: taken, reason = True, "{}!=0".format(reg)
                else: taken, reason = False, "{}==0".format(reg)
            elif mnemo=="cbz":
                if op==0: taken, reason = True, "{}==0".format(reg)
                else: taken, reason = False, "{}!=0".format(reg)
            elif mnemo=="tbnz":
                # operands[1] has one or more white spaces in front, then a #, then the number
                # so we need to eliminate them
                i = int(operands[1].strip().lstrip("#"))
                if (op & 1<<i) != 0: taken, reason = True, "{}&1<<{}!=0".format(reg,i)
                else: taken, reason = False, "{}&1<<{}==0".format(reg,i)
            elif mnemo=="tbz":
                # operands[1] has one or more white spaces in front, then a #, then the number
                # so we need to eliminate them
                i = int(operands[1].strip().lstrip("#"))
                if (op & 1<<i) == 0: taken, reason = True, "{}&1<<{}==0".format(reg,i)
                else: taken, reason = False, "{}&1<<{}!=0".format(reg,i)

        elif mnemo.endswith("eq"): taken, reason = val&(1<<flags["zero"]), "Z"
        elif mnemo.endswith("ne"): taken, reason = val&(1<<flags["zero"]) == 0, "!Z"
        elif mnemo.endswith("lt"): taken, reason = val&(1<<flags["negative"])!=val&(1<<flags["overflow"]), "N!=O"
        elif mnemo.endswith("le"): taken, reason = val&(1<<flags["zero"]) or val&(1<<flags["negative"])!=val&(1<<flags["overflow"]), "Z || N!=O"
        elif mnemo.endswith("gt"): taken, reason = val&(1<<flags["zero"]) == 0 and val&(1<<flags["negative"]) == val&(1<<flags["overflow"]), "!Z && N==O"
        elif mnemo.endswith("ge"): taken, reason = val&(1<<flags["negative"]) == val&(1<<flags["overflow"]), "N==O"
        return taken, reason


class X86(Architecture):
    arch = "X86"
    mode = "32"

    nop_insn = b"\x90"
    flag_register = "$eflags"
    msr_registers = [
        "$cs    ", "$ss    ", "$ds    ", "$es    ", "$fs    ", "$gs    ",
    ]
    gpr_registers = [
        "$eax   ", "$ebx   ", "$ecx   ", "$edx   ", "$esp   ", "$ebp   ", "$esi   ",
        "$edi   ", "$eip   ", ]
    all_registers = gpr_registers + [ flag_register, ] + msr_registers
    instruction_length = None
    return_register = "$eax"
    function_parameters = ["$esp", ]
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
    syscall_instructions = ["sysenter", "int 0x80"]

    def flag_register_to_human(self, val=None):
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"call", "callq"}
        return mnemo in call_mnemos

    def is_ret(self, insn):
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {
            "ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
            "jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
            "jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
            "jo", "jp", "jpe", "js"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        # all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        cx = get_register("$rcx") if self.mode == 64 else get_register("$ecx")

        taken, reason = False, ""

        if mnemo in ("ja", "jnbe"):
            taken, reason = val&(1<<flags["carry"]) == 0 and val&(1<<flags["zero"]) == 0, "!C && !Z"
        elif mnemo in ("jae", "jnb", "jnc"):
            taken, reason = val&(1<<flags["carry"]) == 0, "!C"
        elif mnemo in ("jb", "jc", "jnae"):
            taken, reason = val&(1<<flags["carry"]), "C"
        elif mnemo in ("jbe", "jna"):
            taken, reason = val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "C || Z"
        elif mnemo in ("jcxz", "jecxz", "jrcxz"):
            taken, reason = cx == 0, "!$CX"
        elif mnemo in ("je", "jz"):
            taken, reason = val&(1<<flags["zero"]), "Z"
        elif mnemo in ("jg", "jnle"):
            taken, reason = val&(1<<flags["zero"]) == 0 and val&(1<<flags["overflow"]) == val&(1<<flags["sign"]), "!Z && O==S"
        elif mnemo in ("jge", "jnl"):
            taken, reason = val&(1<<flags["sign"]) == val&(1<<flags["overflow"]), "S==O"
        elif mnemo in ("jl", "jnge"):
            taken, reason = val&(1<<flags["overflow"])!=val&(1<<flags["sign"]), "S!=O"
        elif mnemo in ("jle", "jng"):
            taken, reason = val&(1<<flags["zero"]) or val&(1<<flags["overflow"])!=val&(1<<flags["sign"]), "Z || S!=0"
        elif mnemo in ("jne", "jnz"):
            taken, reason = val&(1<<flags["zero"]) == 0, "!Z"
        elif mnemo in ("jno",):
            taken, reason = val&(1<<flags["overflow"]) == 0, "!O"
        elif mnemo in ("jnp", "jpo"):
            taken, reason = val&(1<<flags["parity"]) == 0, "!P"
        elif mnemo in ("jns",):
            taken, reason = val&(1<<flags["sign"]) == 0, "!S"
        elif mnemo in ("jo",):
            taken, reason = val&(1<<flags["overflow"]), "O"
        elif mnemo in ("jpe", "jp"):
            taken, reason = val&(1<<flags["parity"]), "P"
        elif mnemo in ("js",):
            taken, reason = val&(1<<flags["sign"]), "S"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = to_unsigned_long(dereference(current_arch.sp))
        if frame.older():
            ra = frame.older().pc()

        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 125
        insns = [
            "pushad",
            "mov eax, {:d}".format(_NR_mprotect),
            "mov ebx, {:d}".format(addr),
            "mov ecx, {:d}".format(size),
            "mov edx, {:d}".format(perm),
            "int 0x80",
            "popad",]
        return "; ".join(insns)


class X86_64(X86):
    arch = "X86"
    mode = "64"

    gpr_registers = [
        "$rax   ", "$rbx   ", "$rcx   ", "$rdx   ", "$rsp   ", "$rbp   ", "$rsi   ",
        "$rdi   ", "$rip   ", "$r8    ", "$r9    ", "$r10   ", "$r11   ", "$r12   ",
        "$r13   ", "$r14   ", "$r15   ", ]
    all_registers = gpr_registers + [ X86.flag_register, ] + X86.msr_registers
    return_register = "$rax"
    function_parameters = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    syscall_register = "$rax"
    syscall_instructions = ["syscall"]

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 10
        insns = ["push rax", "push rdi", "push rsi", "push rdx",
                 "mov rax, {:d}".format(_NR_mprotect),
                 "mov rdi, {:d}".format(addr),
                 "mov rsi, {:d}".format(size),
                 "mov rdx, {:d}".format(perm),
                 "syscall",
                 "pop rdx", "pop rsi", "pop rdi", "pop rax"]
        return "; ".join(insns)


class PowerPC(Architecture):
    arch = "PPC"
    mode = "PPC32"

    all_registers = [
        "$r0  ", "$r1  ", "$r2  ", "$r3  ", "$r4  ", "$r5  ", "$r6  ", "$r7  ",
        "$r8  ", "$r9  ", "$r10 ", "$r11 ", "$r12 ", "$r13 ", "$r14 ", "$r15 ",
        "$r16 ", "$r17 ", "$r18 ", "$r19 ", "$r20 ", "$r21 ", "$r22 ", "$r23 ",
        "$r24 ", "$r25 ", "$r26 ", "$r27 ", "$r28 ", "$r29 ", "$r30 ", "$r31 ",
        "$pc  ", "$msr ", "$cr  ", "$lr  ", "$ctr ", "$xer ", "$trap",]
    instruction_length = 4
    nop_insn = b"\x60\x00\x00\x00" # http://www.ibm.com/developerworks/library/l-ppc/index.html
    return_register = "$r0"
    flag_register = "$cr"
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
    function_parameters = ["$i0", "$i1", "$i2", "$i3", "$i4", "$i5"]
    syscall_register = "$r0"
    syscall_instructions = ["sc"]

    def flag_register_to_human(self, val=None):
        # http://www.cebix.net/downloads/bebox/pem32b.pdf (% 2.1.3)
        if not val:
            reg = self.flag_register
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        return False

    def is_ret(self, insn):
        return insn.mnemonic == "blr"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {"beq", "bne", "ble", "blt", "bgt", "bge"}
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""
        if mnemo == "beq": taken, reason = val&(1<<flags["equal[7]"]), "E"
        elif mnemo == "bne": taken, reason = val&(1<<flags["equal[7]"]) == 0, "!E"
        elif mnemo == "ble": taken, reason = val&(1<<flags["equal[7]"]) or val&(1<<flags["less[7]"]), "E || L"
        elif mnemo == "blt": taken, reason = val&(1<<flags["less[7]"]), "L"
        elif mnemo == "bge": taken, reason = val&(1<<flags["equal[7]"]) or val&(1<<flags["greater[7]"]), "E || G"
        elif mnemo == "bgt": taken, reason = val&(1<<flags["greater[7]"]), "G"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        """Ref: http://www.ibm.com/developerworks/library/l-ppc/index.html"""
        _NR_mprotect = 125
        insns = ["addi 1, 1, -16",                 # 1 = r1 = sp
                 "stw 0, 0(1)", "stw 3, 4(1)",     # r0 = syscall_code | r3, r4, r5 = args
                 "stw 4, 8(1)", "stw 5, 12(1)",
                 "li 0, {:d}".format(_NR_mprotect),
                 "lis 3, {:#x}@h".format(addr),
                 "ori 3, 3, {:#x}@l".format(addr),
                 "lis 4, {:#x}@h".format(size),
                 "ori 4, 4, {:#x}@l".format(size),
                 "li 5, {:d}".format(perm),
                 "sc",
                 "lwz 0, 0(1)", "lwz 3, 4(1)",
                 "lwz 4, 8(1)", "lwz 5, 12(1)",
                 "addi 1, 1, 16",]
        return ";".join(insns)


class PowerPC64(PowerPC):
    arch = "PPC"
    mode = "PPC64"


class SPARC(Architecture):
    """ Refs:
    - http://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf
    """
    arch = "SPARC"
    mode = ""

    all_registers = [
        "$g0 ", "$g1 ", "$g2 ", "$g3 ", "$g4 ", "$g5 ", "$g6 ", "$g7 ",
        "$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ", "$o7 ",
        "$l0 ", "$l1 ", "$l2 ", "$l3 ", "$l4 ", "$l5 ", "$l6 ", "$l7 ",
        "$i0 ", "$i1 ", "$i2 ", "$i3 ", "$i4 ", "$i5 ", "$i7 ",
        "$pc ", "$npc", "$sp ", "$fp ", "$psr",]
    instruction_length = 4
    nop_insn = b"\x00\x00\x00\x00"  # sethi 0, %g0
    return_register = "$i0"
    flag_register = "$psr"
    flags_table = {
        23: "negative",
        22: "zero",
        21: "overflow",
        20: "carry",
        7: "supervisor",
        5: "trap",
    }
    function_parameters = ["$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ", "$o7 ",]
    syscall_register = "%g1"
    syscall_instructions = ["t 0x10"]

    def flag_register_to_human(self, val=None):
        # http://www.gaisler.com/doc/sparcv8.pdf
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        return False

    def is_ret(self, insn):
        # TODO: rett?
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        # http://moss.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/condbranch.html
        branch_mnemos = {
            "be", "bne", "bg", "bge", "bgeu", "bgu", "bl", "ble", "blu", "bleu",
            "bneg", "bpos", "bvs", "bvc", "bcs", "bcc"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""

        if mnemo == "be": taken, reason = val&(1<<flags["zero"]), "Z"
        elif mnemo == "bne": taken, reason = val&(1<<flags["zero"]) == 0, "!Z"
        elif mnemo == "bg": taken, reason = val&(1<<flags["zero"]) == 0 and (val&(1<<flags["negative"]) == 0 or val&(1<<flags["overflow"]) == 0), "!Z && (!N || !O)"
        elif mnemo == "bge": taken, reason = val&(1<<flags["negative"]) == 0 or val&(1<<flags["overflow"]) == 0, "!N || !O"
        elif mnemo == "bgu": taken, reason = val&(1<<flags["carry"]) == 0 and val&(1<<flags["zero"]) == 0, "!C && !Z"
        elif mnemo == "bgeu": taken, reason = val&(1<<flags["carry"]) == 0, "!C"
        elif mnemo == "bl": taken, reason = val&(1<<flags["negative"]) and val&(1<<flags["overflow"]), "N && O"
        elif mnemo == "blu": taken, reason = val&(1<<flags["carry"]), "C"
        elif mnemo == "ble": taken, reason = val&(1<<flags["zero"]) or (val&(1<<flags["negative"]) or val&(1<<flags["overflow"])), "Z || (N || O)"
        elif mnemo == "bleu": taken, reason = val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "C || Z"
        elif mnemo == "bneg": taken, reason = val&(1<<flags["negative"]), "N"
        elif mnemo == "bpos": taken, reason = val&(1<<flags["negative"]) == 0, "!N"
        elif mnemo == "bvs": taken, reason = val&(1<<flags["overflow"]), "O"
        elif mnemo == "bvc": taken, reason = val&(1<<flags["overflow"]) == 0, "!O"
        elif mnemo == "bcs": taken, reason = val&(1<<flags["carry"]), "C"
        elif mnemo == "bcc": taken, reason = val&(1<<flags["carry"]) == 0, "!C"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$o7")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        hi = (addr & 0xffff0000) >> 16
        lo = (addr & 0x0000ffff)
        _NR_mprotect = 125
        syscall = "t 0x6d" if is_sparc64() else "t 0x10"
        insns = ["add %sp, -16, %sp",
                 "st %g1, [ %sp ]", "st %o0, [ %sp + 4 ]",
                 "st %o1, [ %sp + 8 ]", "st %o2, [ %sp + 12 ]",
                 "sethi  %hi({}), %o0".format(hi),
                 "or  %o0, {}, %o0".format(lo),
                 "clr  %o1",
                 "clr  %o2",
                 "mov  {}, %g1".format(_NR_mprotect),
                 syscall,
                 "ld [ %sp ], %g1", "ld [ %sp + 4 ], %o0",
                 "ld [ %sp + 8 ], %o1", "ld [ %sp + 12 ], %o2",
                 "add %sp, 16, %sp",]
        return "; ".join(insns)


class SPARC64(SPARC):
    """ Refs:
    - http://math-atlas.sourceforge.net/devel/assembly/abi_sysV_sparc.pdf
    - https://cr.yp.to/2005-590/sparcv9.pdf
    """
    arch = "SPARC"
    mode = "V9"

    all_registers = [
        "$g0   ", "$g1   ", "$g2   ", "$g3   ", "$g4   ", "$g5   ", "$g6   ", "$g7   ",
        "$o0   ", "$o1   ", "$o2   ", "$o3   ", "$o4   ", "$o5   ", "$o7   ",
        "$l0   ", "$l1   ", "$l2   ", "$l3   ", "$l4   ", "$l5   ", "$l6   ", "$l7   ",
        "$i0   ", "$i1   ", "$i2   ", "$i3   ", "$i4   ", "$i5   ", "$i7   ",
        "$pc   ", "$npc  ", "$sp   ", "$fp   ", "$state", ]

    flag_register = "$state" # sparcv9.pdf, 5.1.5.1 (ccr)
    flags_table = {
        35: "negative",
        34: "zero",
        33: "overflow",
        32: "carry",
    }

    syscall_instructions = ["t 0x6d"]



class MIPS(Architecture):
    arch = "MIPS"
    mode = "MIPS32"

    # http://vhouten.home.xs4all.nl/mipsel/r3000-isa.html
    all_registers = [
        "$zero     ", "$at       ", "$v0       ", "$v1       ", "$a0       ", "$a1       ", "$a2       ", "$a3       ",
        "$t0       ", "$t1       ", "$t2       ", "$t3       ", "$t4       ", "$t5       ", "$t6       ", "$t7       ",
        "$s0       ", "$s1       ", "$s2       ", "$s3       ", "$s4       ", "$s5       ", "$s6       ", "$s7       ",
        "$t8       ", "$t9       ", "$k0       ", "$k1       ", "$s8       ", "$pc       ", "$sp       ", "$hi       ",
        "$lo       ", "$fir      ", "$ra       ", "$gp       ", ]
    instruction_length = 4
    nop_insn = b"\x00\x00\x00\x00" # sll $0,$0,0
    return_register = "$v0"
    flag_register = "$fcsr"
    flags_table = {}
    function_parameters = ["$a0", "$a1", "$a2", "$a3"]
    syscall_register = "$v0"
    syscall_instructions = ["syscall"]

    def flag_register_to_human(self, val=None):
        return Color.colorify("No flag register", attrs="yellow underline")

    def is_call(self, insn):
        return False

    def is_ret(self, insn):
        return insn.mnemonic == "jr" and insn.operands[0] == "ra"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {"beq", "bne", "beqz", "bnez", "bgtz", "bgez", "bltz", "blez"}
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        taken, reason = False, ""

        if mnemo == "beq":
            taken, reason = get_register(ops[0]) == get_register(ops[1]), "{0[0]} == {0[1]}".format(ops)
        elif mnemo == "bne":
            taken, reason = get_register(ops[0]) != get_register(ops[1]), "{0[0]} != {0[1]}".format(ops)
        elif mnemo == "beqz":
            taken, reason = get_register(ops[0]) == 0, "{0[0]} == 0".format(ops)
        elif mnemo == "bnez":
            taken, reason = get_register(ops[0]) != 0, "{0[0]} != 0".format(ops)
        elif mnemo == "bgtz":
            taken, reason = get_register(ops[0]) > 0, "{0[0]} > 0".format(ops)
        elif mnemo == "bgez":
            taken, reason = get_register(ops[0]) >= 0, "{0[0]} >= 0".format(ops)
        elif mnemo == "bltz":
            taken, reason = get_register(ops[0]) < 0, "{0[0]} < 0".format(ops)
        elif mnemo == "blez":
            taken, reason = get_register(ops[0]) <= 0, "{0[0]} <= 0".format(ops)
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$ra")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 4125
        insns = ["addi $sp, $sp, -16",
                 "sw $v0, 0($sp)", "sw $a0, 4($sp)",
                 "sw $a3, 8($sp)", "sw $a3, 12($sp)",
                 "li $v0, {:d}".format(_NR_mprotect),
                 "li $a0, {:d}".format(addr),
                 "li $a1, {:d}".format(size),
                 "li $a2, {:d}".format(perm),
                 "syscall",
                 "lw $v0, 0($sp)", "lw $a1, 4($sp)",
                 "lw $a3, 8($sp)", "lw $a3, 12($sp)",
                 "addi $sp, $sp, 16",]
        return "; ".join(insns)


def write_memory(address, buffer, length=0x10):
    """Write `buffer` at address `address`."""
    if PYTHON_MAJOR == 2: buffer = str(buffer)
    return gdb.selected_inferior().write_memory(address, buffer, length)


def read_memory(addr, length=0x10):
    """Return a `length` long byte array with the copy of the process memory at `addr`."""
    if PYTHON_MAJOR == 2:
        return gdb.selected_inferior().read_memory(addr, length)

    return gdb.selected_inferior().read_memory(addr, length).tobytes()


def read_int_from_memory(addr):
    """Return an integer from memory."""
    sz = get_memory_alignment()
    mem = read_memory(addr, sz)
    fmt = "{}{}".format(endian_str(), "I" if sz==4 else "Q")
    return struct.unpack(fmt, mem)[0]


def read_cstring_from_memory(address, max_length=GEF_MAX_STRING_LENGTH, encoding=None):
    """Return a C-string from memory."""
    if not encoding:
        encoding = "unicode_escape" if PYTHON_MAJOR==3 else "ascii"

    char_t = cached_lookup_type("char")
    char_ptr = char_t.pointer()
    res = gdb.Value(address).cast(char_ptr).string(encoding=encoding).strip()
    res2 = res.replace('\n','\\n').replace('\r','\\r').replace('\t','\\t')

    if max_length and len(res) > max_length:
        return "{}[...]".format(res2[:max_length])

    return res2


def is_readable_string(address):
    """Tries to determine if the content pointed by `address` is
    a readable string by checking if:
    * the last element is 0x00 (i.e. it is a C-string)
    * each byte is printable"""
    try:
        cstr = read_cstring_from_memory(address)
        return isinstance(cstr, unicode) and cstr and all([x in string.printable for x in cstr])
    except UnicodeDecodeError:
        return False


def is_alive():
    """Check if GDB is running."""
    try:
        return gdb.selected_inferior().pid > 0
    except:
        return False
    return False


def only_if_gdb_running(f):
    """Decorator wrapper to check if GDB is running."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_alive():
            return f(*args, **kwargs)
        else:
            warn("No debugging session active")
    return wrapper


def only_if_gdb_target_local(f):
    """Decorator wrapper to check if GDB is running locally (target not remote)."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_remote_debug():
            return f(*args, **kwargs)
        else:
            warn("This command cannot work for remote sessions.")
    return wrapper


def experimental_feature(f):
    """Decorator to add a warning when a feature is experimental."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        warn("This feature is under development, expect bugs and unstability...")
        return f(*args, **kwargs)
    return wrapper


def only_if_gdb_version_higher_than(required_gdb_version):
    """Decorator to check whether current GDB version requirements."""
    def wrapper(f):
        def inner_f(*args, **kwargs):
            if GDB_VERSION >= required_gdb_version:
                f(*args, **kwargs)
            else:
                reason = "GDB >= {} for this command".format(required_gdb_version)
                raise EnvironmentError(reason)
        return inner_f
    return wrapper


def use_stdtype():
    if   is_elf32(): return "uint32_t"
    elif is_elf64(): return "uint64_t"
    return "uint16_t"


def use_default_type():
    if   is_elf32(): return "unsigned int"
    elif is_elf64(): return "unsigned long"
    return "unsigned short"


def use_golang_type():
    if   is_elf32(): return "uint32"
    elif is_elf64(): return "uint64"
    return "uint16"


def to_unsigned_long(v):
    """Cast a gdb.Value to unsigned long."""
    unsigned_long_t = cached_lookup_type(use_stdtype()) \
                      or cached_lookup_type(use_default_type()) \
                      or cached_lookup_type(use_golang_type())
    return long(v.cast(unsigned_long_t))


def get_register(regname):
    """Return a register's value."""
    regname = regname.strip()
    try:
        value = gdb.parse_and_eval(regname)
        return to_unsigned_long(value) if value.type.code == gdb.TYPE_CODE_INT else long(value)
    except gdb.error:
        value = gdb.selected_frame().read_register(regname)
        return long(value)


def get_path_from_info_proc():
    for x in gdb.execute("info proc", to_string=True).splitlines():
        if x.startswith("exe = "):
            return x.split(" = ")[1].replace("'", "")
    return None


@lru_cache()
def get_os():
    """Return the current OS."""
    return platform.system().lower()


@lru_cache()
def get_pid():
    """Return the currently debugged PID."""
    return gdb.selected_inferior().pid


@lru_cache()
def get_filepath():
    """Return the local absolute path of the file currently debugged."""
    filename = gdb.current_progspace().filename

    if is_remote_debug():
        # if no filename specified, try downloading target from /proc
        if filename is None:
            pid = get_pid()
            if pid > 0:
                return download_file("/proc/{:d}/exe".format(pid), use_cache=True)
            return None

        # if target is remote file, download
        elif filename.startswith("target:"):
            fname = filename[len("target:"):]
            return download_file(fname, use_cache=True, local_name=fname)

        elif __gef_remote__ is not None:
            return "/tmp/gef/{:d}/{:s}".format(__gef_remote__, get_path_from_info_proc())
        return filename
    else:
        if filename is not None:
            return filename
        # inferior probably did not have name, extract cmdline from info proc
        return get_path_from_info_proc()


@lru_cache()
def get_filename():
    """Return the full filename of the file currently debugged."""
    return os.path.basename(get_filepath())


def download_file(target, use_cache=False, local_name=None):
    """Download filename `target` inside the mirror tree inside the GEF_TEMP_DIR.
    The tree architecture must be GEF_TEMP_DIR/gef/<local_pid>/<remote_filepath>.
    This allow a "chroot-like" tree format."""

    try:
        local_root = os.path.sep.join([GEF_TEMP_DIR, str(get_pid())])
        if local_name is None:
            local_path = os.path.sep.join([local_root, os.path.dirname(target)])
            local_name = os.path.sep.join([local_path, os.path.basename(target)])
        else:
            local_path = os.path.sep.join([local_root, os.path.dirname(local_name)])
            local_name = os.path.sep.join([local_path, os.path.basename(local_name)])

        if use_cache and os.access(local_name, os.R_OK):
            return local_name

        gef_makedirs(local_path)
        gdb.execute("remote get {0:s} {1:s}".format(target, local_name))

    except gdb.error:
        # gdb-stub compat
        with open(local_name, "w") as f:
            if is_elf32():
                f.write("00000000-ffffffff rwxp 00000000 00:00 0                    {}\n".format(get_filepath()))
            else:
                f.write("0000000000000000-ffffffffffffffff rwxp 00000000 00:00 0                    {}\n".format(get_filepath()))

    except Exception as e:
        err("download_file() failed: {}".format(str(e)))
        local_name = None
    return local_name


def open_file(path, use_cache=False):
    """Attempt to open the given file, if remote debugging is active, download
    it first to the mirror in /tmp/"""
    if is_remote_debug():
        lpath = download_file(path, use_cache)
        if not lpath:
            raise IOError("cannot open remote path {:s}".format(path))
        path = lpath

    return open(path, "r")


def get_function_length(sym):
    """Attempt to get the length of the raw bytes of a function."""
    dis = gdb.execute("disassemble {:s}".format(sym), to_string=True).splitlines()
    start_addr = int(dis[1].split()[0], 16)
    end_addr = int(dis[-2].split()[0], 16)
    return end_addr - start_addr


def get_process_maps_linux(proc_map_file):
    """Parse the Linux process `/proc/pid/maps` file."""
    for line in open_file(proc_map_file, use_cache=False):
        line = line.strip()
        addr, perm, off, _, rest = line.split(" ", 4)
        rest = rest.split(" ", 1)
        if len(rest) == 1:
            inode = rest[0]
            pathname = ""
        else:
            inode = rest[0]
            pathname = rest[1].replace(" ", "")

        addr_start, addr_end = list(map(lambda x: long(x, 16), addr.split("-")))
        off = long(off, 16)
        perm = Permission.from_process_maps(perm)

        yield Section(page_start=addr_start,
                      page_end=addr_end,
                      offset=off,
                      permission=perm,
                      inode=inode,
                      path=pathname)
    return


@lru_cache()
def get_process_maps():
    """Parse the `/proc/pid/maps` file."""

    sections = []
    try:
        pid = get_pid()
        fpath = "/proc/{:d}/maps".format(pid)
        sections = get_process_maps_linux(fpath)
        return list(sections)

    except FileNotFoundError as e:
        warn("Failed to read /proc/<PID>/maps, using GDB sections info: {}".format(e))
        return list(get_info_sections())


@lru_cache()
def get_info_sections():
    """Retrieves the debuggee sections."""
    stream = StringIO(gdb.execute("maintenance info sections", to_string=True))

    for line in stream:
        if not line:
            break

        try:
            parts = [x.strip() for x in line.split()]
            addr_start, addr_end = [long(x, 16) for x in parts[1].split("->")]
            off = long(parts[3][:-1], 16)
            path = parts[4]
            inode = ""
            perm = Permission.from_info_sections(parts[5:])

            yield Section(page_start=addr_start,
                          page_end=addr_end,
                          offset=off,
                          permission=perm,
                          inode=inode,
                          path=path)

        except IndexError:
            continue
        except ValueError:
            continue

    return


@lru_cache()
def get_info_files():
    """Retrieves all the files loaded by debuggee."""
    lines = gdb.execute("info files", to_string=True).splitlines()

    if len(lines) < len(__infos_files__):
        return __infos_files__

    for line in lines:
        line = line.strip().rstrip()

        if not line:
            break

        if not line.startswith("0x"):
            continue

        blobs = [x.strip() for x in line.split(" ")]
        addr_start = long(blobs[0], 16)
        addr_end = long(blobs[2], 16)
        section_name = blobs[4]

        if len(blobs) == 7:
            filename = blobs[6]
        else:
            filename = get_filepath()

        info = Zone()
        info.name = section_name
        info.zone_start = addr_start
        info.zone_end = addr_end
        info.filename = filename

        __infos_files__.append(info)

    return __infos_files__


def process_lookup_address(address):
    """Look up for an address in memory.
    Return an Address object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    if is_x86_64() or is_x86_32() :
        if is_in_x86_kernel(address):
            return None

    for sect in get_process_maps():
        if sect.page_start <= address < sect.page_end:
            return sect

    return None


def process_lookup_path(name, perm=Permission.ALL):
    """Look up for a path in the process memory mapping.
    Return a Section object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    for sect in get_process_maps():
        if name in sect.path and sect.permission.value & perm:
            return sect

    return None


def file_lookup_address(address):
    """Look up for a file by its address.
    Return a Zone object if found, None otherwise."""
    for info in get_info_files():
        if info.zone_start <= address < info.zone_end:
            return info
    return None


def lookup_address(address):
    """Tries to find the address in the process address space.
    Return an Address object, with validity flag set based on success."""
    sect = process_lookup_address(address)
    info = file_lookup_address(address)
    if sect is None and info is None:
        # i.e. there is no info on this address
        return Address(value=address, valid=False)
    return Address(value=address, section=sect, info=info)


def xor(data, key):
    """Return `data` xor-ed with `key`."""
    key = key.lstrip("0x")
    key = binascii.unhexlify(key)
    if PYTHON_MAJOR == 2:
        return b"".join([chr(ord(x) ^ ord(y)) for x, y in zip(data, itertools.cycle(key))])

    return bytearray([x ^ y for x, y in zip(data, itertools.cycle(key))])


def is_hex(pattern):
    """Return whether provided string is a hexadecimal value."""
    if not pattern.startswith("0x") and not pattern.startswith("0X"):
        return False
    return len(pattern)%2==0 and all(c in string.hexdigits for c in pattern[2:])


def ida_synchronize_handler(event):
    gdb.execute("ida-interact Sync", from_tty=True, to_string=True)
    return


def continue_handler(event):
    """GDB event handler for new object continue cases."""
    return


def hook_stop_handler(event):
    """GDB event handler for stop cases."""
    reset_all_caches()
    gdb.execute("context")
    return


def new_objfile_handler(event):
    """GDB event handler for new object file cases."""
    reset_all_caches()
    set_arch()
    return


def exit_handler(event):
    """GDB event handler for exit cases."""
    global __gef_remote__, __gef_qemu_mode__

    reset_all_caches()
    __gef_qemu_mode__ = False
    if __gef_remote__ and get_gef_setting("gef-remote.clean_on_exit") == True:
        shutil.rmtree("/tmp/gef/{:d}".format(__gef_remote__))
        __gef_remote__ = None
    return


def get_terminal_size():
    """Return the current terminal size."""
    if is_debug():
        return 600, 100

    try:
        cmd = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))
        tty_rows, tty_columns = int(cmd[0]), int(cmd[1])
        return tty_rows, tty_columns

    except OSError:
        return 600, 100


def get_generic_arch(module, prefix, arch, mode, big_endian, to_string=False):
    """
    Retrieves architecture and mode from the arguments for use for the holy
    {cap,key}stone/unicorn trinity.
    """
    if to_string:
        arch = "{:s}.{:s}_ARCH_{:s}".format(module.__name__, prefix, arch)
        if mode:
            mode = "{:s}.{:s}_MODE_{:s}".format(module.__name__, prefix, str(mode))
        else:
            mode = ""
        if is_big_endian():
            mode += " + {:s}.{:s}_MODE_BIG_ENDIAN".format(module.__name__, prefix)
        else:
            mode += " + {:s}.{:s}_MODE_LITTLE_ENDIAN".format(module.__name__, prefix)

    else:
        arch = getattr(module, "{:s}_ARCH_{:s}".format(prefix, arch))
        if mode:
            mode = getattr(module, "{:s}_MODE_{:s}".format(prefix, mode))
        else:
            mode = 0
        if big_endian:
            mode |= getattr(module, "{:s}_MODE_BIG_ENDIAN".format(prefix))
        else:
            mode |= getattr(module, "{:s}_MODE_LITTLE_ENDIAN".format(prefix))

    return arch, mode


def get_generic_running_arch(module, prefix, to_string=False):
    """
    Retrieves architecture and mode from the current context.
    """

    if not is_alive():
        return None, None

    if current_arch is not None:
        arch, mode = current_arch.arch, current_arch.mode
    else:
        raise OSError("Emulation not supported for your OS")

    return get_generic_arch(module, prefix, arch, mode, is_big_endian(), to_string)


def get_unicorn_arch(arch=None, mode=None, endian=None, to_string=False):
    unicorn = sys.modules["unicorn"]
    if (arch, mode, endian) == (None,None,None):
        return get_generic_running_arch(unicorn, "UC", to_string)
    return get_generic_arch(unicorn, "UC", arch, mode, endian, to_string)


def get_capstone_arch(arch=None, mode=None, endian=None, to_string=False):
    capstone = sys.modules["capstone"]

    # hacky patch to unify capstone/ppc syntax with keystone & unicorn:
    # CS_MODE_PPC32 does not exist (but UC_MODE_32 & KS_MODE_32 do)
    if is_alive() and (is_powerpc() or is_ppc64()):
        if is_ppc64():
            raise OSError("Capstone not supported for PPC64 yet.")

        arch = "PPC"
        mode = "32"
        endian = is_big_endian()
        return get_generic_arch(capstone, "CS",
                                arch or current_arch.arch,
                                mode or current_arch.mode,
                                endian or is_big_endian(),
                                to_string)

    if (arch, mode, endian) == (None,None,None):
        return get_generic_running_arch(capstone, "CS", to_string)
    return get_generic_arch(capstone, "CS",
                            arch or current_arch.arch,
                            mode or current_arch.mode,
                            endian or is_big_endian(),
                            to_string)


def get_keystone_arch(arch=None, mode=None, endian=None, to_string=False):
    keystone = sys.modules["keystone"]
    if (arch, mode, endian) == (None,None,None):
        return get_generic_running_arch(keystone, "KS", to_string)
    return get_generic_arch(keystone, "KS", arch, mode, endian, to_string)


def get_unicorn_registers(to_string=False):
    "Return a dict matching the Unicorn identifier for a specific register."
    unicorn = sys.modules["unicorn"]
    regs = {}

    if current_arch is not None:
        arch = current_arch.arch.lower()
    else:
        raise OSError("Oops")

    const = getattr(unicorn, "{}_const".format(arch))
    for reg in current_arch.all_registers:
        regname = "UC_{:s}_REG_{:s}".format(arch.upper(), reg.strip()[1:].upper())
        if to_string:
            regs[reg] = "{:s}.{:s}".format(const.__name__, regname)
        else:
            regs[reg] = getattr(const, regname)
    return regs


def keystone_assemble(code, arch, mode, *args, **kwargs):
    """Assembly encoding function based on keystone."""
    keystone = sys.modules["keystone"]
    code = gef_pybytes(code)
    addr = kwargs.get("addr", 0x1000)

    try:
        ks = keystone.Ks(arch, mode)
        enc, cnt = ks.asm(code, addr)
    except keystone.KsError as e:
        err("Keystone assembler error: {:s}".format(str(e)))
        return None

    if cnt==0:
        return ""

    enc = bytearray(enc)
    if "raw" not in kwargs:
        s = binascii.hexlify(enc)
        enc = b"\\x" + b"\\x".join([s[i:i + 2] for i in range(0, len(s), 2)])
        enc = enc.decode("utf-8")

    return enc


@lru_cache()
def get_elf_headers(filename=None):
    """Return an Elf object with info from `filename`. If not provided, will return
    the currently debugged file."""
    if filename is None:
        filename = get_filepath()

    if filename.startswith("target:"):
        warn("Your file is remote, you should try using `gef-remote` instead")
        return

    return Elf(filename)


@lru_cache()
def is_elf64(filename=None):
    """Checks if `filename` is an ELF64."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_class == Elf.ELF_64_BITS


@lru_cache()
def is_elf32(filename=None):
    """Checks if `filename` is an ELF32."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_class == Elf.ELF_32_BITS


@lru_cache()
def is_x86_64(filename=None):
    """Checks if `filename` is an x86-64 ELF."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_machine == Elf.X86_64


@lru_cache()
def is_x86_32(filename=None):
    """Checks if `filename` is an x86-32 ELF."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_machine == Elf.X86_32


@lru_cache()
def is_arm(filename=None):
    """Checks if `filename` is an ARM ELF."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_machine == Elf.ARM


@lru_cache()
def is_arm_thumb():
    """Checks if `filename` is an ARM (THUMB mode) ELF."""
    return is_arm() and is_alive() and get_register("$cpsr") & (1<<5)


@lru_cache()
def is_mips():
    """Checks if `filename` is a MIPS ELF."""
    elf = current_elf or get_elf_headers()
    return elf.e_machine == Elf.MIPS


@lru_cache()
def is_powerpc():
    """Checks if `filename` is a PowerPC ELF."""
    elf = current_elf or get_elf_headers()
    return elf.e_machine == Elf.POWERPC


@lru_cache()
def is_ppc64():
    """Checks if `filename` is a PowerPC64 ELF."""
    elf = current_elf or get_elf_headers()
    return elf.e_machine == Elf.POWERPC64


@lru_cache()
def is_sparc():
    """Checks if `filename` is a SPARC ELF."""
    elf = current_elf or get_elf_headers()
    return elf.e_machine == Elf.SPARC


@lru_cache()
def is_sparc64():
    """Checks if `filename` is a SPARC64 ELF."""
    elf = current_elf or get_elf_headers()
    return elf.e_machine == Elf.SPARC64


@lru_cache()
def is_aarch64():
    """Checks if `filename` is a AARCH64 ELF."""
    elf = current_elf or get_elf_headers()
    return elf.e_machine == Elf.AARCH64


def set_arch(arch=None, default=None):
    """Sets the current architecture.
    If an arch is explicitly specified, use that one, otherwise try to parse it
    out of the ELF header. If that fails, and default is specified, select and
    set that arch.
    Return the selected arch, or raise an OSError.
    """
    arches = {
        "ARM": ARM, Elf.ARM: ARM,
        "AARCH64": AARCH64, "ARM64": AARCH64, Elf.AARCH64: AARCH64,
        "X86": X86, Elf.X86_32: X86,
        "X86_64": X86_64, Elf.X86_64: X86_64,
        "PowerPC": PowerPC, "PPC": PowerPC, Elf.POWERPC: PowerPC,
        "PowerPC64": PowerPC64, "PPC64": PowerPC64, Elf.POWERPC64: PowerPC64,
        "SPARC": SPARC, Elf.SPARC: SPARC,
        "SPARC64": SPARC64, Elf.SPARC64: SPARC64,
        "MIPS": MIPS, Elf.MIPS: MIPS,
    }
    global current_arch, current_elf

    if arch:
        try:
            current_arch = arches[arch.upper()]()
            return current_arch
        except KeyError:
            raise OSError("Specified arch {:s} is not supported".format(arch.upper()))

    current_elf = current_elf or get_elf_headers()
    try:
        current_arch = arches[current_elf.e_machine]()
    except KeyError:
        if default:
            try:
                current_arch = arches[default.upper()]()
            except KeyError:
                raise OSError("CPU not supported, neither is default {:s}".format(default.upper()))
        else:
            raise OSError("CPU type is currently not supported: {:s}".format(get_arch()))
    return current_arch


@lru_cache()
def cached_lookup_type(_type):
    try:
        return gdb.lookup_type(_type).strip_typedefs()
    except RuntimeError:
        return None


def get_memory_alignment(in_bits=False):
    """Return sizeof(size_t). If `in_bits` is set to True, the result is
    returned in bits, otherwise in bytes."""
    res = cached_lookup_type('size_t')
    if res is not None:
        return res.sizeof if not in_bits else res.sizeof * 8
    if is_elf32():
        return 4 if not in_bits else 32
    elif is_elf64():
        return 8 if not in_bits else 64
    raise EnvironmentError("GEF is running under an unsupported mode")


def clear_screen(tty=""):
    """Clear the screen."""
    if not tty:
        gdb.execute("shell clear")
        return

    with open(tty, "w") as f:
        f.write("\x1b[H\x1b[J")
    return


def format_address(addr):
    """Format the address according to its size."""
    memalign_size = get_memory_alignment()
    addr = align_address(addr)

    if memalign_size == 4:
        return "0x{:08x}".format(addr)

    return "0x{:016x}".format(addr)


def format_address_spaces(addr, left=True):
    """Format the address according to its size, but with spaces instead of zeroes."""
    width = get_memory_alignment() * 2 + 2
    addr = align_address(addr)

    if not left:
        return "0x{:x}".format(addr).rjust(width)

    return "0x{:x}".format(addr).ljust(width)


def align_address(address):
    """Align the provided address to the process's native length."""
    if get_memory_alignment(in_bits=True) == 32:
        return address & 0xFFFFFFFF

    return address & 0xFFFFFFFFFFFFFFFF


def align_address_to_page(address):
    """Align the address to a page."""
    a = align_address(address) >> DEFAULT_PAGE_ALIGN_SHIFT
    return a << DEFAULT_PAGE_ALIGN_SHIFT


def parse_address(address):
    """Parse an address and return it as an Integer."""
    if is_hex(address):
        return long(address, 16)
    return to_unsigned_long(gdb.parse_and_eval(address))


def is_in_x86_kernel(address):
    address = align_address(address)
    memalign = get_memory_alignment(in_bits=True) - 1
    return (address >> memalign) == 0xF


@lru_cache()
def endian_str():
    elf = current_elf or get_elf_headers()
    return "<" if elf.e_endianness == Elf.LITTLE_ENDIAN else ">"


@lru_cache()
def is_remote_debug():
    """"Return True is the current debugging session is running through GDB remote session."""
    return __gef_remote__ is not None or "remote" in gdb.execute("maintenance print target-stack", to_string=True)


def de_bruijn(alphabet, n):
    """De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib)."""
    k = len(alphabet)
    a = [0] * k * n
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c
    return db(1,1)


def generate_cyclic_pattern(length):
    """Create a `length` byte bytearray of a de Bruijn cyclic pattern."""
    charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
    cycle = get_memory_alignment()
    res = bytearray()

    for i, c in enumerate(de_bruijn(charset, cycle)):
        if i == length:
            break
        res.append(c)

    return res


def safe_parse_and_eval(value):
    """GEF wrapper for gdb.parse_and_eval(): this function returns None instead of raising
    gdb.error if the eval failed."""
    try:
        return gdb.parse_and_eval(value)
    except gdb.error:
        return None


def dereference(addr):
    """GEF wrapper for gdb dereference function."""
    try:
        ulong_t = cached_lookup_type(use_stdtype()) or \
                  cached_lookup_type(use_default_type()) or \
                  cached_lookup_type(use_golang_type())
        unsigned_long_type = ulong_t.pointer()
        res = gdb.Value(addr).cast(unsigned_long_type).dereference()
        # GDB does lazy fetch by default so we need to force access to the value
        res.fetch_lazy()
        return res
    except gdb.MemoryError:
        pass
    return None


def dereference_as_long(addr):
    derefed = dereference(addr)
    return long(derefed.address) if derefed is not None else 0


def gef_convenience(value):
    """Defines a new convenience value."""
    global __gef_convenience_vars_index__
    var_name = "$_gef{:d}".format(__gef_convenience_vars_index__)
    __gef_convenience_vars_index__ += 1
    gdb.execute("""set {:s} = "{:s}" """.format(var_name, value))
    return var_name


@lru_cache()
def gef_get_auxiliary_values():
    """Retrieves the auxiliary values of the current execution. Returns None if not running, or a dict()
    of values."""
    if not is_alive():
        return None

    res = {}
    for line in gdb.execute("info auxv", to_string=True).splitlines():
        tmp = line.split()
        _type = tmp[1]
        if _type in ("AT_PLATFORM", "AT_EXECFN"):
            idx = line[:-1].rfind('"') - 1
            tmp = line[:idx].split()

        res[_type] = int(tmp[-1], base=0)
    return res


def gef_read_canary():
    """Read the canary of a running process using Auxiliary Vector. Return a tuple of (canary, location)
    if found, None otherwise."""
    auxval = gef_get_auxiliary_values()
    if not auxval:
        return None

    canary_location = auxval["AT_RANDOM"]
    canary = read_int_from_memory(canary_location)
    canary &= ~0xff
    return canary, canary_location


def gef_get_pie_breakpoint(num):
    global __pie_breakpoints__
    return __pie_breakpoints__[num]


@lru_cache()
def gef_getpagesize():
    """Get the page size from auxiliary values."""
    auxval = gef_get_auxiliary_values()
    if not auxval:
        return DEFAULT_PAGE_SIZE
    return auxval["AT_PAGESZ"]


def only_if_events_supported(event_type):
    """Checks if GDB supports events without crashing."""
    def wrap(f):
        def wrapped_f(*args, **kwargs):
            if getattr(gdb, "events") and getattr(gdb.events, event_type):
                return f(*args, **kwargs)
            warn("GDB events cannot be set")
        return wrapped_f
    return wrap


#
# Event hooking
#

@only_if_events_supported("cont")
def gef_on_continue_hook(func): return gdb.events.cont.connect(func)
@only_if_events_supported("cont")
def gef_on_continue_unhook(func): return gdb.events.cont.disconnect(func)

@only_if_events_supported("stop")
def gef_on_stop_hook(func): return gdb.events.stop.connect(func)
@only_if_events_supported("stop")
def gef_on_stop_unhook(func): return gdb.events.stop.disconnect(func)

@only_if_events_supported("exited")
def gef_on_exit_hook(func): return gdb.events.exited.connect(func)
@only_if_events_supported("exited")
def gef_on_exit_unhook(func): return gdb.events.exited.disconnect(func)

@only_if_events_supported("new_objfile")
def gef_on_new_hook(func): return gdb.events.new_objfile.connect(func)
@only_if_events_supported("new_objfile")
def gef_on_new_unhook(func): return gdb.events.new_objfile.disconnect(func)


#
# Virtual breakpoints
#

class PieVirtualBreakpoint(object):
    """PIE virtual breakpoint (not real breakpoint)."""
    def __init__(self, set_func, vbp_num, addr):
        # set_func(base): given a base address return a
        # set breakpoint gdb command string
        self.set_func = set_func
        self.vbp_num = vbp_num
        # breakpoint num, 0 represents not instantiated yet
        self.bp_num = 0
        self.bp_addr = 0
        # this address might be a symbol, just to know where to break
        if isinstance(addr, int):
            self.addr = hex(addr)
        else:
            self.addr = addr

    def instantiate(self, base):
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
        # Breakpoint (no) at (addr)
        self.bp_num = res_list[1]
        self.bp_addr = res_list[3]

    def destroy(self):
        if not self.bp_num:
            err("Destroy PIE breakpoint not even set")
            return
        gdb.execute("delete {}".format(self.bp_num))
        self.bp_num = 0

#
# Breakpoints
#

class FormatStringBreakpoint(gdb.Breakpoint):
    """Inspect stack for format string"""
    def __init__(self, spec, num_args):
        super(FormatStringBreakpoint, self).__init__(spec, type=gdb.BP_BREAKPOINT, internal=False)
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self):
        msg = []
        if is_x86_32():
            sp = current_arch.sp
            sz =  get_memory_alignment()
            val = sp + (self.num_args * sz) + sz
            ptr = read_int_from_memory(val)
            addr = lookup_address(ptr)
            ptr = hex(ptr)
        else:
            regs = current_arch.function_parameters
            ptr = regs[self.num_args]
            addr = lookup_address(get_register(ptr))

        if not addr.valid:
            return False

        if addr.section.permission.value & Permission.WRITE:
            content = read_cstring_from_memory(addr.value)
            name = addr.info.name if addr.info else addr.section.path
            msg.append(Color.colorify("Format string helper", attrs="yellow bold"))
            msg.append("Possible insecure format string: {:s}('{:s}' {:s} {:#x}: '{:s}')".format(self.location, ptr, RIGHT_ARROW, addr.value, content))
            msg.append("Reason: Call to '{:s}()' with format string argument in position "
                       "#{:d} is in page {:#x} ({:s}) that has write permission".format(self.location, self.num_args, addr.section.page_start, name))
            push_context_message("warn", "\n".join(msg))
            return True

        return False


class StubBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.)"""

    def __init__(self, func, retval):
        super(StubBreakpoint, self).__init__(func, gdb.BP_BREAKPOINT, internal=False)
        self.func = func
        self.retval = retval

        m = "All calls to '{:s}' will be skipped".format(self.func)
        if self.retval is not None:
            m += " (with return value set to {:#x})".format(self.retval)
        info(m)
        return

    def stop(self):
        m = "Ignoring call to '{:s}' ".format(self.func)
        m+= "(setting return value to {:#x})".format(self.retval)
        gdb.execute("return (unsigned int){:#x}".format(self.retval))
        ok(m)
        return False


class ChangePermissionBreakpoint(gdb.Breakpoint):
    """When hit, this temporary breakpoint will restore the original code, and position
    $pc correctly."""

    def __init__(self, loc, code, pc):
        super(ChangePermissionBreakpoint, self).__init__(loc, gdb.BP_BREAKPOINT, internal=False)
        self.original_code = code
        self.original_pc = pc
        return

    def stop(self):
        info("Restoring original context")
        write_memory(self.original_pc, self.original_code, len(self.original_code))
        info("Restoring $pc")
        gdb.execute("set $pc = {:#x}".format(self.original_pc))
        return True


class TraceMallocBreakpoint(gdb.Breakpoint):
    """Track allocations done with malloc() or calloc."""

    def __init__(self, name):
        super(TraceMallocBreakpoint, self).__init__(name, gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self):
        if is_x86_32():
            # if intel x32, the malloc size is in the stack, so we need to dereference $sp
            size = to_unsigned_long(dereference( current_arch.sp+4 ))
        else:
            size = get_register(current_arch.function_parameters[0])
        self.retbp = TraceMallocRetBreakpoint(size)
        return False



class TraceMallocRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to retrieve the return value of malloc()."""

    def __init__(self, size):
        super(TraceMallocRetBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.size = size
        self.silent = True
        return


    def stop(self):
        global __heap_uaf_watchpoints__, __heap_freed_list__, __heap_allocated_list__

        if self.return_value:
            loc = long(self.return_value)
        else:
            loc = to_unsigned_long(gdb.parse_and_eval(current_arch.return_register))

        size = self.size
        ok("{} - malloc({})={:#x}".format(Color.colorify("Heap-Analysis", attrs="yellow bold"), size, loc))
        check_heap_overlap = get_gef_setting("heap-analysis-helper.check_heap_overlap")

        # pop from free-ed list if it was in it
        if __heap_freed_list__:
            idx = 0
            for item in __heap_freed_list__:
                addr = item[0]
                if addr==loc:
                    __heap_freed_list__.remove(item)
                    continue
                idx+=1

        # pop from uaf watchlist
        if __heap_uaf_watchpoints__:
            idx = 0
            for wp in __heap_uaf_watchpoints__:
                wp_addr = wp.address
                if loc <= wp_addr < loc+size:
                    __heap_uaf_watchpoints__.remove(wp)
                    wp.enabled = False
                    continue
                idx+=1

        item = (loc, size)

        if check_heap_overlap:
            # seek all the currently allocated chunks, read their effective size and check for overlap
            msg = []
            align = get_memory_alignment()
            for chunk_addr, _ in __heap_allocated_list__:
                current_chunk = GlibcChunk(chunk_addr)
                current_chunk_size = current_chunk.get_chunk_size()

                if chunk_addr <= loc < chunk_addr + current_chunk_size:
                    offset = loc - chunk_addr - 2*align
                    if offset < 0: continue # false positive, discard

                    msg.append(Color.colorify("Heap-Analysis", attrs="yellow bold"))
                    msg.append("Possible heap overlap detected")
                    msg.append("Reason {} new allocated chunk {:#x} (of size {:d}) overlaps in-used chunk {:#x} (of size {:#x})".format(RIGHT_ARROW, loc, size, chunk_addr, current_chunk_size))
                    msg.append("Writing {0:d} bytes from {1:#x} will reach chunk {2:#x}".format(offset, chunk_addr, loc))
                    msg.append("Payload example for chunk {1:#x} (to overwrite {0:#x} headers):".format(loc, chunk_addr))
                    msg.append("  data = 'A'*{0:d} + 'B'*{1:d} + 'C'*{1:d}".format(offset, align))
                    push_context_message("warn", "\n".join(msg))
                    return True

        # add it to alloc-ed list
        __heap_allocated_list__.append(item)
        return False


class TraceReallocBreakpoint(gdb.Breakpoint):
    """Track re-allocations done with realloc()."""

    def __init__(self):
        super(TraceReallocBreakpoint, self).__init__("__libc_realloc", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self):
        if is_x86_32():
            ptr = to_unsigned_long(dereference( current_arch.sp+4 ))
            size = to_unsigned_long(dereference( current_arch.sp+8 ))
        else:
            ptr = get_register(current_arch.function_parameters[0])
            size = get_register(current_arch.function_parameters[1])
        self.retbp = TraceReallocRetBreakpoint(ptr, size)
        return False


class TraceReallocRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to retrieve the return value of realloc()."""

    def __init__(self, ptr, size):
        super(TraceReallocRetBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.ptr = ptr
        self.size = size
        self.silent = True
        return

    def stop(self):
        global __heap_uaf_watchpoints__, __heap_freed_list__, __heap_allocated_list__

        if self.return_value:
            newloc = long(self.return_value)
        else:
            newloc = to_unsigned_long(gdb.parse_and_eval(current_arch.return_register))

        if newloc != self:
            ok("{} - realloc({:#x}, {})={}".format(Color.colorify("Heap-Analysis", attrs="yellow bold"),
                                                   self.ptr, self.size,
                                                   Color.colorify("{:#x}".format(newloc), attrs="green"),))
        else:
            ok("{} - realloc({:#x}, {})={}".format(Color.colorify("Heap-Analysis", attrs="yellow bold"),
                                                   self.ptr, self.size,
                                                   Color.colorify("{:#x}".format(newloc), attrs="red"),))

        item = (newloc, self.size)

        try:
            # check if item was in alloc-ed list
            idx = [x for x,y in __heap_allocated_list__].index(self.ptr)
            # if so pop it out
            item = __heap_allocated_list__.pop(idx)
        except ValueError:
            if is_debug():
                warn("Chunk {:#x} was not in tracking list".format(self.ptr))
        finally:
            # add new item to alloc-ed list
            __heap_allocated_list__.append(item)

        return False


class TraceFreeBreakpoint(gdb.Breakpoint):
    """Track calls to free() and attempts to detect inconsistencies."""

    def __init__(self):
        super(TraceFreeBreakpoint, self).__init__("__libc_free", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self):
        if is_x86_32():
            # if intel x32, the free address is in the stack, so we need to dereference $sp
            addr = to_unsigned_long(dereference( current_arch.sp+4 ))
        else:
            addr = long(gdb.parse_and_eval(current_arch.function_parameters[0]))
        msg = []
        check_free_null = get_gef_setting("heap-analysis-helper.check_free_null")
        check_double_free = get_gef_setting("heap-analysis-helper.check_double_free")
        check_weird_free = get_gef_setting("heap-analysis-helper.check_weird_free")
        check_uaf = get_gef_setting("heap-analysis-helper.check_uaf")

        ok("{} - free({:#x})".format(Color.colorify("Heap-Analysis", attrs="yellow bold"), addr))
        if addr==0:
            if check_free_null:
                msg.append(Color.colorify("Heap-Analysis", attrs="yellow bold"))
                msg.append("Attempting to free(NULL) at {:#x}".format(current_arch.pc))
                msg.append("Reason: if NULL page is allocatable, this can lead to code execution.")
                push_context_message("warn", "\n".join(msg))
                return True
            return False


        if addr in [x for (x,y) in __heap_freed_list__]:
            if check_double_free:
                msg.append(Color.colorify("Heap-Analysis", attrs="yellow bold"))
                msg.append("Double-free detected {} free({:#x}) is called at {:#x} but is already in the free-ed list".format(RIGHT_ARROW, addr, current_arch.pc))
                msg.append("Execution will likely crash...")
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        # if here, no error
        # 1. move alloc-ed item to free list
        try:
            # pop from alloc-ed list
            idx = [x for x,y in __heap_allocated_list__].index(addr)
            item = __heap_allocated_list__.pop(idx)

        except ValueError:
            if check_weird_free:
                msg.append(Color.colorify("Heap-Analysis", attrs="yellow bold"))
                msg.append("Heap inconsistency detected:")
                msg.append("Attempting to free an unknown value: {:#x}".format(addr))
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        # 2. add it to free-ed list
        __heap_freed_list__.append(item)

        self.retbp = None
        if check_uaf:
            # 3. (opt.) add a watchpoint on pointer
            self.retbp = TraceFreeRetBreakpoint(addr)
        return False


class TraceFreeRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to track free-ed values."""

    def __init__(self, addr):
        super(TraceFreeRetBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.silent = True
        self.addr = addr
        return

    def stop(self):
        wp = UafWatchpoint(self.addr)
        __heap_uaf_watchpoints__.append(wp)
        ok("{} - watching {:#x}".format(Color.colorify("Heap-Analysis", attrs="yellow bold"), self.addr))
        return False


class UafWatchpoint(gdb.Breakpoint):
    """Custom watchpoints set TraceFreeBreakpoint() to monitor free-ed pointers being used."""

    def __init__(self, addr):
        super(UafWatchpoint, self).__init__("*{:#x}".format(addr), gdb.BP_WATCHPOINT, internal=True)
        self.address = addr
        self.silent = True
        self.enabled = True
        return

    def stop(self):
        """If this method is triggered, we likely have a UaF. Break the execution and report it."""
        frame = gdb.selected_frame()
        if frame.name() in ("_int_malloc", "malloc_consolidate", "__libc_calloc"):
            # ignore when the watchpoint is raised by malloc() - due to reuse
            return False

        pc = gdb_get_nth_previous_instruction_address(current_arch.pc, 2) # software watchpoints stop after the next statement (see https://sourceware.org/gdb/onlinedocs/gdb/Set-Watchpoints.html)
        insn = gef_current_instruction(pc)
        msg = []
        msg.append(Color.colorify("Heap-Analysis", attrs="yellow bold"))
        msg.append("Possible Use-after-Free in '{:s}': pointer {:#x} was freed, but is attempted to be used at {:#x}".format(get_filepath(), self.address, pc))
        msg.append("{:#x}   {:s} {:s}".format(insn.address, insn.mnemonic, Color.yellowify(", ".join(insn.operands))))
        push_context_message("warn", "\n".join(msg))
        return True


class EntryBreakBreakpoint(gdb.Breakpoint):
    """Breakpoint used internally to stop execution at the most convenient entry point."""

    def __init__(self, location):
        super(EntryBreakBreakpoint, self).__init__(location, gdb.BP_BREAKPOINT, internal=True, temporary=True)
        self.silent = True
        return

    def stop(self):
        return True


#
# Commands
#

def register_external_command(obj):
    """Registering function for new GEF (sub-)command to GDB."""
    global __commands__, __gef__
    cls = obj.__class__
    __commands__.append(cls)
    __gef__.load(initial=False)
    __gef__.doc.add_command_to_doc((cls._cmdline_, cls, None))
    __gef__.doc.refresh()
    return cls


def register_command(cls):
    """Decorator for registering new GEF (sub-)command to GDB."""
    global __commands__
    __commands__.append(cls)
    return cls


def register_priority_command(cls):
    """Decorator for registering new command with priority, meaning that it must
    loaded before the other generic commands."""
    global __commands__
    __commands__.insert(0, cls)
    return cls


class GenericCommand(gdb.Command):
    """This is an abstract class for invoking commands, should not be instantiated."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, *args, **kwargs):
        self.pre_load()
        syntax = Color.yellowify("\nSyntax: ") + self._syntax_
        example = Color.yellowify("\nExample: ") + self._example_ if self._example_ else ""
        self.__doc__ = self.__doc__.replace(" "*4, "") + syntax + example
        command_type = kwargs.setdefault("command", gdb.COMMAND_OBSCURE)
        complete_type = kwargs.setdefault("complete", gdb.COMPLETE_NONE)
        prefix = kwargs.setdefault("prefix", False)
        super(GenericCommand, self).__init__(self._cmdline_, command_type, complete_type, prefix)
        self.post_load()
        return

    def invoke(self, args, from_tty):
        try:
            argv = gdb.string_to_argv(args)
            #bufferize(self.do_invoke(argv))
            self.do_invoke(argv)
        except Exception as e:
            # Note: since we are intercepting cleaning exceptions here, commands preferably should avoid
            # catching generic Exception, but rather specific ones. This is allows a much cleaner use.
            if is_debug():
                show_last_exception()
            else:
                err("Command '{:s}' failed to execute properly, reason: {:s}".format(self._cmdline_, str(e)))
        return

    def usage(self):
        err("Syntax\n{}".format(self._syntax_))
        return

    @abc.abstractproperty
    def _cmdline_(self): pass

    @abc.abstractproperty
    def _syntax_(self): pass

    @abc.abstractproperty
    def _example_(self): return ""

    @abc.abstractmethod
    def do_invoke(self, argv): pass

    def pre_load(self): pass

    def post_load(self): pass

    def __get_setting_name(self, name):
        def __sanitize_class_name(clsname):
            if " " not in clsname:
                return clsname
            return "-".join(clsname.split())

        class_name = __sanitize_class_name(self.__class__._cmdline_)
        return "{:s}.{:s}".format(class_name, name)

    @property
    def settings(self):
        """Return the list of settings for this command."""
        return [ x.split(".", 1)[1] for x in __config__
                 if x.startswith("{:s}.".format(self._cmdline_)) ]

    def get_setting(self, name):
        key = self.__get_setting_name(name)
        setting = __config__[key]
        return setting[1](setting[0])

    def has_setting(self, name):
        key = self.__get_setting_name(name)
        return key in __config__

    def add_setting(self, name, value, description=""):
        key = self.__get_setting_name(name)
        __config__[key] = [value, type(value), description]
        return

    def del_setting(self, name):
        key = self.__get_setting_name(name)
        del __config__[key]
        return


# Copy/paste this template for new command
# @register_command
# class TemplateCommand(GenericCommand):
# """TemplateCommand: description here will be seen in the help menu for the command."""
#     _cmdline_ = "template-fake"
#     _syntax_  = "{:s}".format(_cmdline_)
#     _aliases_ = ["tpl-fk",]
#     def __init__(self):
#        super(TemplateCommand, self).__init__(complete=gdb.COMPLETE_FILENAME)
#         return
#     def do_invoke(self, argv):
#         return

@register_command
class PrintFormatCommand(GenericCommand):
    """Print bytes format in high level languages"""

    _cmdline_ = "print-format"
    _syntax_  = "{:s} [-f FORMAT] [-b BITSIZE] [-l LENGTH] [-c] [-h] LOCATION".format(_cmdline_)
    _aliases_ = ["pf",]
    _example_ = "{0:s} -f py -b 8 -l 256 $rsp".format(_cmdline_)

    bitformat = {8: '<B', 16: '<H', 32: '<I', 64: '<Q'}
    c_type = {8: 'char', 16: 'short', 32: 'int', 64: 'long long'}
    asm_type = {8: 'db', 16: 'dw', 32: 'dd', 64: 'dq'}

    def __init__(self):
        super(PrintFormatCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def usage(self):
        h = self._syntax_
        h += "\n\t-f FORMAT specifies the output format for programming language, avaliable value is py, c, js, asm (default py).\n"
        h += "\t-b BITSIZE sepecifies size of bit, avaliable values is 8, 16, 32, 64 (default is 8).\n"
        h += "\t-l LENGTH specifies length of array (default is 256).\n"
        h += "\t-c The result of data will copied to clipboard\n"
        h += "\tLOCATION specifies where the address of bytes is stored."
        info(h)
        return

    def clip(self, data):
        if sys.platform == "linux":
            xclip = which("xclip")
            prog = [xclip, "-selection", "clipboard", "-i"] # For linux
        elif sys.platform == "darwin":
            pbcopy = which("pbcopy")
            prog = [pbcopy] # For OSX
        else:
            warn("Can't copy to clipboard, platform not supported")
            return False

        try:
            p = subprocess.Popen(prog, stdin=subprocess.PIPE)
        except Exception:
            warn("Can't copy to clipboard, Something went wrong while copying")
            return False

        p.stdin.write(data)
        p.stdin.close()
        retcode = p.wait()
        return True

    @only_if_gdb_running
    def do_invoke(self, argv):
        """Default value for print-format command"""
        lang = 'py'
        length = 256
        bitlen = 8
        copy_to_clipboard = False
        supported_formats = ['py', 'c', 'js', 'asm']

        opts, args = getopt.getopt(argv, "f:l:b:ch")
        for o,a in opts:
            if   o == "-f": lang = a
            elif o == "-l": length = long(gdb.parse_and_eval(a))
            elif o == "-b": bitlen = long(a)
            elif o == "-c": copy_to_clipboard = True
            elif o == '-h':
                self.usage()
                return

        if len(args) < 1:
            err("No address specified")
            return

        start_addr = long(gdb.parse_and_eval(args[0]))

        if bitlen not in [8, 16, 32, 64]:
            err("Size of bit must be in 8, 16, 32, or 64")
            return

        if lang not in supported_formats:
            err("Language must be : {}".format(str(supported_formats)))
            return

        size = long(bitlen / 8)
        end_addr = start_addr+length*size
        bf = self.bitformat[bitlen]
        data = []
        out = ""

        for address in range(start_addr, end_addr, size):
            value = struct.unpack(bf, read_memory(address, size))[0]
            data += [value]
        sdata = ", ".join(map(hex, data))

        if lang == 'py':
            out = 'buf = [{}]'.format(sdata)

        elif lang == 'c':
            out =  'unsigned {0} buf[{1}] = {{{2}}};'.format(self.c_type[bitlen], length, sdata)

        elif lang == 'js':
            out =  'var buf = [{}]'.format(s_data)

        elif lang == 'asm':
            out += 'buf {0} {1}'.format(self.asm_type[bitlen], sdata)

        if copy_to_clipboard:
            if self.clip(bytes(out, 'utf-8')):
                info("Copied to clipboard")
            else:
                warn("There's a problem while copying")

        print(out)
        return


@register_command
class PieCommand(GenericCommand):
    """PIE breakpoint support."""

    _cmdline_ = "pie"
    _syntax_  = "{:s} (breakpoint|info|delete|run|attach|remote)".format(_cmdline_)

    def __init__(self):
        super(PieCommand, self).__init__(prefix=True)
        return

    def do_invoke(self, argv):
        if not argv:
            self.usage()
        return


@register_command
class PieBreakpointCommand(GenericCommand):
    """Set a PIE breakpoint."""

    _cmdline_ = "pie breakpoint"
    _syntax_  = "{:s} BREAKPOINT".format(_cmdline_)

    def do_invoke(self, argv):
        global __pie_counter__, __pie_breakpoints__
        if len(argv) < 1:
            self.usage()
            return
        bp_expr = " ".join(argv)
        tmp_bp_expr = bp_expr
        bp_expr = bp_expr[1:].replace(" ", "")
        try:
            addr = int(bp_expr, 0)
            self.set_pie_breakpoint(lambda base: "b *{}".format(base + addr), addr)
        except ValueError:
            bp_expr = tmp_bp_expr
            self.set_pie_breakpoint(lambda base: "b {}".format(bp_expr), bp_expr)

        # When the process is already on, set real breakpoints immediately
        if is_alive():
            vmmap = get_process_maps()
            base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]

            for bp_ins in __pie_breakpoints__.values():
                bp_ins.instantiate(base_address)


    @staticmethod
    def set_pie_breakpoint(set_func, addr):
        global __pie_counter__, __pie_breakpoints__
        __pie_breakpoints__[__pie_counter__] = PieVirtualBreakpoint(set_func, __pie_counter__, addr)
        __pie_counter__ += 1


@register_command
class PieInfoCommand(GenericCommand):
    """Display breakpoint info."""

    _cmdline_ = "pie info"
    _syntax_  = "{:s} BREAKPOINT".format(_cmdline_)

    def do_invoke(self, argv):
        global __pie_breakpoints__
        if len(argv) < 1:
            # No breakpoint info needed
            bps = [__pie_breakpoints__[x] for x in __pie_breakpoints__]
        else:
            try:
                bps = [__pie_breakpoints__[int(x)] for x in argv]
            except ValueError:
                err("Please give me breakpoint number")
                return
        lines = []
        lines.append("VNum\tNum\tAddr")
        lines += [
            "{}\t{}\t{}".format(x.vbp_num, x.bp_num if x.bp_num else "N/A", x.addr) for x in bps
        ]
        gef_print("\n".join(lines))


@register_command
class PieDeleteCommand(GenericCommand):
    """Delete a PIE breakpoint."""

    _cmdline_ = "pie delete"
    _syntax_  = "{:s} [BREAKPOINT]".format(_cmdline_)

    def do_invoke(self, argv):
        global __pie_breakpoints__
        if len(argv) < 1:
            # no arg, delete all
            to_delete = [__pie_breakpoints__[x] for x in __pie_breakpoints__]
            self.delete_bp(to_delete)
        try:
            self.delete_bp([__pie_breakpoints__[int(x)] for x in argv])
        except ValueError:
            err("Please input PIE virtual breakpoint number to delete")

    @staticmethod
    def delete_bp(breakpoints):
        global __pie_breakpoints__
        for bp in breakpoints:
            # delete current real breakpoints if exists
            gdb.execute(
                "delete {}".format(bp.bp_num)
            ) if bp.bp_num else 0
            # delete virtual breakpoints
            del __pie_breakpoints__[bp.vbp_num]


@register_command
class PieRunCommand(GenericCommand):
    """Run process with PIE breakpoint support."""

    _cmdline_ = "pie run"
    _syntax_  = _cmdline_

    def do_invoke(self, argv):
        global __pie_breakpoints__
        fpath = get_filepath()
        if fpath is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn("The file '{}' is not executable.".format(fpath))
            return

        if is_alive():
            warn("gdb is already running. Restart process.")

        # get base address
        gdb.execute("set stop-on-solib-events 1")
        disable_context()
        gdb.execute("run {}".format(" ".join(argv)))
        enable_context()
        gdb.execute("set stop-on-solib-events 0")
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        info("base address {}".format(hex(base_address)))

        # modify all breakpoints
        for bp_ins in __pie_breakpoints__.values():
            bp_ins.instantiate(base_address)

        try:
            gdb.execute("continue")
        except gdb.error as e:
            err(e)
            gdb.execute("kill")


@register_command
class PieAttachCommand(GenericCommand):
    """Do attach with PIE breakpoint support."""

    _cmdline_ = "pie attach"
    _syntax_  = "{:s} PID".format(_cmdline_)

    def do_invoke(self, argv):
        try:
            gdb.execute("attach {}".format(" ".join(argv)), to_string=True)
        except gdb.error as e:
            err(e)
            return
        # after attach, we are stopped so that we can
        # get base address to modify our breakpoint
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]

        for bp_ins in __pie_breakpoints__.values():
            bp_ins.instantiate(base_address)
        gdb.execute("context")


@register_command
class PieRemoteCommand(GenericCommand):
    """Attach to a remote connection with PIE breakpoint support."""

    _cmdline_ = "pie remote"
    _syntax_  = "{:s} REMOTE".format(_cmdline_)

    def do_invoke(self, argv):
        try:
            gdb.execute("gef-remote {}".format(" ".join(argv)))
        except gdb.error as e:
            err(e)
            return
        # after remote attach, we are stopped so that we can
        # get base address to modify our breakpoint
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.realpath == get_filepath()][0]

        for bp_ins in __pie_breakpoints__.values():
            bp_ins.instantiate(base_address)
        gdb.execute("context")


@register_command
class SmartEvalCommand(GenericCommand):
    """SmartEval: Smart eval (vague approach to mimic WinDBG `?`)."""
    _cmdline_ = "$"
    _syntax_  = "{0:s} EXPR\n{0:s} ADDRESS1 ADDRESS2".format(_cmdline_)
    _example_ = "\n{0:s} $pc+1\n{0:s} 0x00007ffff7a10000 0x00007ffff7bce000".format(_cmdline_)

    def do_invoke(self, argv):
        argc = len(argv)
        if argc==1:
            self.evaluate(argv)
            return

        if argc==2:
            self.distance(argv)
        return

    def evaluate(self, expr):
        def show_as_int(i):
            off = current_arch.ptrsize*8
            def comp2_x(x): return "{:x}".format((x + (1 << off)) % (1 << off))
            def comp2_b(x): return "{:b}".format((x + (1 << off)) % (1 << off))

            try:
                s_i = comp2_x(res)
                s_i = s_i.rjust(len(s_i)+1, "0") if len(s_i)%2 else s_i
                gef_print("{:d}".format(i))
                gef_print("0x" + comp2_x(res))
                gef_print("0b" + comp2_b(res))
                gef_print("{}".format(binascii.unhexlify(s_i)))
                gef_print("{}".format(binascii.unhexlify(s_i)[::-1]))
            except:
                pass
            return

        parsed_expr = []
        for xp in expr:
            try:
                xp = gdb.parse_and_eval(xp)
                xp = int(xp)
                parsed_expr.append("{:d}".format(xp))
            except gdb.error:
                parsed_expr.append(str(xp))

        try:
            res = eval(" ".join(parsed_expr))
            if type(res) is int:
                show_as_int(res)
            else:
                gef_print("{}".format(res))
        except SyntaxError:
            gef_print(" ".join(parsed_expr))
        return

    def distance(self, args):
        try:
            x = int(args[0], 16) if is_hex(args[0]) else int(args[0])
            y = int(args[1], 16) if is_hex(args[1]) else int(args[1])
            gef_print("{}".format(abs(x-y)))
        except ValueError:
            warn("Distance requires 2 numbers: {} 0 0xffff".format(self._cmdline_))
        return


@register_command
class CanaryCommand(GenericCommand):
    """Shows the canary value of the current process. Apply the techique detailed in
    https://www.elttam.com.au/blog/playing-with-canaries/ to show the canary."""

    _cmdline_ = "canary"
    _syntax_  = _cmdline_

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.dont_repeat()

        has_canary = checksec(get_filepath())["Canary"]
        if not has_canary:
            warn("This binary was not compiled with SSP.")
            return

        res = gef_read_canary()
        if not res:
            err("Failed to get the canary")
            return

        canary, location = res
        info("Found AT_RANDOM at {:#x}, reading {} bytes".format(location, current_arch.ptrsize))
        info("The canary of process {} is {:#x}".format(get_pid(), canary))
        return


@register_command
class ProcessStatusCommand(GenericCommand):
    """Extends the info given by GDB `info proc`, by giving an exhaustive description of the
    process status (file descriptors, ancestor, descendants, etc.). """

    _cmdline_ = "process-status"
    _syntax_  = _cmdline_
    _aliases_ = ["status", ]

    def __init__(self):
        super(ProcessStatusCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        return

    @only_if_gdb_running
    @only_if_gdb_target_local
    def do_invoke(self, argv):
        self.show_info_proc()
        self.show_ancestor()
        self.show_descendants()
        self.show_fds()
        self.show_connections()
        return

    def get_state_of(self, pid):
        res = {}
        for line in open("/proc/{}/status".format(pid), "r"):
            key, value = line.split(":", 1)
            res[key.strip()] = value.strip()
        return res

    def get_cmdline_of(self, pid):
        return open("/proc/{}/cmdline".format(pid), "r").read().replace("\x00", "\x20").strip()

    def get_process_path_of(self, pid):
        return os.readlink("/proc/{}/exe".format(pid))

    def get_children_pids(self, pid):
        ps = which("ps")
        cmd = [ps, "-o", "pid", "--ppid","{}".format(pid), "--noheaders"]
        try:
            return [int(x) for x in gef_execute_external(cmd, as_list=True)]
        except Exception:
            return []

    def show_info_proc(self):
        info("Process Information")
        pid = get_pid()
        cmdline = self.get_cmdline_of(pid)
        gef_print("\tPID {} {}".format(RIGHT_ARROW, pid))
        gef_print("\tExecutable {} {}".format(RIGHT_ARROW, self.get_process_path_of(pid)))
        gef_print("\tCommand line {} '{}'".format(RIGHT_ARROW, cmdline))
        return

    def show_ancestor(self):
        info("Parent Process Information")
        ppid = int(self.get_state_of(get_pid())["PPid"])
        state = self.get_state_of(ppid)
        cmdline = self.get_cmdline_of(ppid)
        gef_print("\tParent PID {} {}".format(RIGHT_ARROW, state["Pid"]))
        gef_print("\tCommand line {} '{}'".format(RIGHT_ARROW, cmdline))
        return

    def show_descendants(self):
        info("Children Process Information")
        children = self.get_children_pids(get_pid())
        if not children:
            gef_print("\tNo child process")
            return

        for child_pid in children:
            state = self.get_state_of(child_pid)
            pid = state["Pid"]
            gef_print("\tPID {} {} (Name: '{}', CmdLine: '{}')".format(RIGHT_ARROW,
                                                                       pid,
                                                                       self.get_process_path_of(pid),
                                                                       self.get_cmdline_of(pid)))
            return

    def show_fds(self):
        pid = get_pid()
        path = "/proc/{:d}/fd".format(pid)

        info("File Descriptors:")
        items = os.listdir(path)
        if not items:
            gef_print("\tNo FD opened")
            return

        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath):
                gef_print("\t{:s} {:s} {:s}".format (fullpath, RIGHT_ARROW, os.readlink(fullpath)))
        return

    def list_sockets(self, pid):
        sockets = []
        path = "/proc/{:d}/fd".format(pid)
        items = os.listdir(path)
        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath) and os.readlink(fullpath).startswith("socket:"):
                p = os.readlink(fullpath).replace("socket:", "")[1:-1]
                sockets.append(int(p))
        return sockets

    def parse_ip_port(self, addr):
        ip, port = addr.split(":")
        return socket.inet_ntoa(struct.pack("<I", int(ip, 16))), int(port, 16)

    def show_connections(self):
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
            0x0a: "TCP_LISTEN",
            0x0b: "TCP_CLOSING",
            0x0c: "TCP_NEW_SYN_RECV",
        }

        udp_states_str = {
            0x07: "UDP_LISTEN",
        }

        info("Network Connections")
        pid = get_pid()
        sockets = self.list_sockets(pid)
        if not sockets:
            gef_print("\tNo open connections")
            return

        entries = {}
        entries["TCP"] = [x.split() for x in open("/proc/{:d}/net/tcp".format(pid), "r").readlines()[1:]]
        entries["UDP"]= [x.split() for x in open("/proc/{:d}/net/udp".format(pid), "r").readlines()[1:]]

        for proto in entries:
            for entry in entries[proto]:
                local, remote, state = entry[1:4]
                inode = int(entry[9])
                if inode in sockets:
                    local = self.parse_ip_port(local)
                    remote = self.parse_ip_port(remote)
                    state = int(state, 16)
                    state_str = tcp_states_str[state] if proto=="TCP" else udp_states_str[state]

                    gef_print("\t{}:{} {} {}:{} ({})".format(local[0], local[1],
                                                             RIGHT_ARROW,
                                                             remote[0], remote[1],
                                                             state_str))
        return


@register_priority_command
class GefThemeCommand(GenericCommand):
    """Customize GEF appearance."""
    _cmdline_ = "theme"
    _syntax_  = "{:s} [KEY [VALUE]]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefThemeCommand, self).__init__(GefThemeCommand._cmdline_)
        self.add_setting("context_title_line", "green bold", "Color of the borders in context window")
        self.add_setting("context_title_message", "red bold", "Color of the title in context window")
        self.add_setting("default_title_line", "green bold", "Default color of borders")
        self.add_setting("default_title_message", "red bold", "Default color of title")
        self.add_setting("xinfo_title_message", "blue bold", "Color of the title in xinfo window")
        self.add_setting("disassemble_current_instruction", "bold red", "Color to use to highlight the current $pc when disassembling")
        self.add_setting("dereference_string", "green", "Color of dereferenced string")
        self.add_setting("dereference_code", "red", "Color of dereferenced code")
        self.add_setting("dereference_base_address", "bold green", "Color of dereferenced address")
        self.add_setting("dereference_register_value", "bold green" , "Color of dereferenced register")
        self.add_setting("registers_register_name", "bold red", "Color of the register name in the register window")
        self.add_setting("registers_value_changed", "bold red", "Color of the changed register in the register window")
        self.add_setting("address_stack", "pink", "Color to use when a stack address is found")
        self.add_setting("address_heap", "yellow", "Color to use when a heap address is found")
        self.add_setting("address_code", "red", "Color to use when a code address is found")
        self.add_setting("source_current_line", "bold red", "Color to use for the current code line in the source window")
        return

    def do_invoke(self, args):
        self.dont_repeat()
        argc = len(args)

        if argc==0:
            for setting in sorted(self.settings):
                value = self.get_setting(setting)
                value = Color.colorify(value, attrs=value)
                gef_print("{:40s}: {:s}".format(setting, value))
            return

        setting = args[0]
        if not self.has_setting(setting):
            err("Invalid key")
            return

        if argc==1:
            value = self.get_setting(setting)
            value = Color.colorify(value, attrs=value)
            gef_print("{:40s}: {:s}".format(setting, value))
            return

        val = [x for x in args[1:] if x in Color.colors]
        self.add_setting(setting, " ".join(val))
        return


@register_command
class PCustomCommand(GenericCommand):
    """Dump user defined structure.
    This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows
    to apply structures (from symbols or custom) directly to an address.
    Custom structures can be defined in pure Python using ctypes, and should be stored
    in a specific directory, whose path must be stored in the `pcustom.struct_path`
    configuration setting."""

    _cmdline_ = "pcustom"
    _syntax_  = "{:s} [-l] [StructA [0xADDRESS] [-e]]".format(_cmdline_)

    def __init__(self):
        super(PCustomCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL)
        self.add_setting("struct_path", os.path.join(GEF_TEMP_DIR, "structs"),
                         "Path to store/load the structure ctypes files")
        return

    def do_invoke(self, argv):
        argc = len(argv)
        if argc == 0:
            self.usage()
            return

        if argv[0] == "-l":
            self.list_custom_structures()
            return

        modname, structname = argv[0].split(":", 1) if ":" in argv[0] else (argv[0], argv[0])
        structname = structname.split(".", 1)[0] if "." in structname else structname

        if argc == 1:
            self.dump_structure(modname, structname)
            return

        if argv[1] == "-e":
            self.create_or_edit_structure(modname, structname)
            return

        if not is_alive():
            return

        try:
            address = long(gdb.parse_and_eval(argv[1]))
        except gdb.error:
            err("Failed to parse '{:s}'".format(argv[1]))
            return

        self.apply_structure_to_address(modname, structname, address)
        return


    def get_struct_path(self):
        path = os.path.expanduser(self.get_setting("struct_path"))
        path = os.path.realpath(path)
        return path if os.path.isdir(path) else None


    def pcustom_filepath(self, x):
        p = self.get_struct_path()
        if not p: return None
        return os.path.join(p, "{}.py".format(x))


    def is_valid_struct(self, x):
        p = self.pcustom_filepath(x)
        return os.access(p, os.R_OK) if p else None


    def dump_structure(self, mod_name, struct_name):
        # If it's a builtin or defined in the ELF use gdb's `ptype`
        try:
            gdb.execute("ptype struct {:s}".format(struct_name))
            return
        except gdb.error:
            pass

        self.dump_custom_structure(mod_name, struct_name)
        return


    def dump_custom_structure(self, mod_name, struct_name):
        if not self.is_valid_struct(mod_name):
            err("Invalid structure name '{:s}'".format(struct_name))
            return

        _class = self.get_class(mod_name, struct_name)
        _offset = 0

        for _name, _type in _class._fields_:
            _size = ctypes.sizeof(_type)
            gef_print("+{:04x} {:s} {:s} ({:#x})".format(_offset, _name, _type.__name__, _size))
            _offset += _size
        return


    def deserialize(self, struct, data):
        length = min(len(data), ctypes.sizeof(struct))
        ctypes.memmove(ctypes.addressof(struct), data, length)
        return


    def get_module(self, modname):
        _fullname = self.pcustom_filepath(modname)
        return imp.load_source(modname, _fullname)


    def get_class(self, modname, classname):
        _mod = self.get_module(modname)
        return getattr(_mod, classname)()


    def list_all_structs(self, modname):
        _mod = self.get_module(modname)
        _invalid = set(["BigEndianStructure", "LittleEndianStructure", "Structure"])
        _structs = set([x for x in dir(_mod) \
                         if inspect.isclass(getattr(_mod, x)) \
                         and issubclass(getattr(_mod, x), ctypes.Structure)])
        return _structs - _invalid


    def apply_structure_to_address(self, mod_name, struct_name, addr, depth=0):
        if not self.is_valid_struct(mod_name):
            err("Invalid structure name '{:s}'".format(struct_name))
            return

        try:
            _class = self.get_class(mod_name, struct_name)
            data = read_memory(addr, ctypes.sizeof(_class))
        except gdb.MemoryError:
            err("{}Cannot reach memory {:#x}".format(' '*depth, addr))
            return

        self.deserialize(_class, data)

        _regsize = get_memory_alignment()
        _offset = 0

        for field in _class._fields_:
            _name, _type = field
            _size = ctypes.sizeof(_type)
            _value = getattr(_class, _name)

            if    (_regsize == 4 and _type is ctypes.c_uint32) \
               or (_regsize == 8 and _type is ctypes.c_uint64) \
               or (_regsize == ctypes.sizeof(ctypes.c_void_p) and _type is ctypes.c_void_p):
                # try to dereference pointers
                _value = RIGHT_ARROW.join(DereferenceCommand.dereference_from(_value))

            line = []
            line += "  "*depth
            line += ("{:#x}+0x{:04x} {} : ".format(addr, _offset, _name)).ljust(40)
            line += "{} ({})".format(_value, _type.__name__)
            parsed_value = self.get_ctypes_value(_class, _name, _value)
            if parsed_value:
                line += " {} {}".format(RIGHT_ARROW, parsed_value)
            gef_print("".join(line))

            if issubclass(_type, ctypes.Structure):
                self.apply_structure_to_address(mod_name, _type.__name__, addr + _offset, depth + 1)
                _offset += ctypes.sizeof(_type)
            else:
                _offset += _size
        return


    def get_ctypes_value(self, struct, item, value):
        if not hasattr(struct, "_values_"): return ""
        values_list = getattr(struct, "_values_")
        default = ""
        for name, values in values_list:
            if name != item: continue
            if callable(values):
                return values(value)
            else:
                try:
                    for val, desc in values:
                        if value == val: return desc
                        if val is None: default = desc
                except:
                    err("Error while trying to obtain values from _values_[\"{}\"]".format(name))

        return default


    def create_or_edit_structure(self, mod_name, struct_name):
        path = self.get_struct_path()
        if path is None:
            err("Invalid struct path")
            return

        fullname = self.pcustom_filepath(mod_name)
        if not self.is_valid_struct(mod_name):
            info("Creating '{:s}' from template".format(fullname))
            with open(fullname, "wb") as f:
                f.write(self.get_template(struct_name))
                f.flush()
        else:
            info("Editing '{:s}'".format(fullname))

        cmd = os.getenv("EDITOR").split() if os.getenv("EDITOR") else ["nano",]
        cmd.append(fullname)
        retcode = subprocess.call(cmd)
        return retcode


    def get_template(self, structname):
        d = [
            b"from ctypes import *\n\n",
            b"class ",
            gef_pybytes(structname),
            b"(Structure):\n",
            b"    _fields_ = []\n"
        ]
        return b"".join(d)


    def list_custom_structures(self):
        path = self.get_struct_path()
        if path is None:
            err("Cannot open '{0}': check directory and/or `gef config {0}` "
                "setting, currently: '{1}'".format("pcustom.struct_path", self.get_setting("struct_path")))
            return

        info("Listing custom structures from '{:s}'".format(path))
        for filen in os.listdir(path):
            name, ext = os.path.splitext(filen)
            if ext != ".py": continue
            _modz = self.list_all_structs(name)
            ok("{:s} {:s} ({:s})".format(RIGHT_ARROW, name, ", ".join(_modz)))
        return


@register_command
class ChangeFdCommand(GenericCommand):
    """ChangeFdCommand: redirect file descriptor during runtime."""

    _cmdline_ = "hijack-fd"
    _syntax_  = "{:s} FD_NUM NEW_OUTPUT".format(_cmdline_)
    _example_ = "{:s} 2 /tmp/stderr_output.txt".format(_cmdline_)

    @only_if_gdb_running
    @only_if_gdb_target_local
    def do_invoke(self, argv):
        if len(argv)!=2:
            self.usage()
            return

        if not os.access("/proc/{:d}/fd/{:s}".format(get_pid(), argv[0]), os.R_OK):
            self.usage()
            return

        old_fd = int(argv[0])
        new_output = argv[1]

        disable_context()

        if ':' in new_output:
            address = socket.gethostbyname(new_output.split(":")[0])
            port = int(new_output.split(":")[1])

            # socket(int domain, int type, int protocol)
            # AF_INET = 2, SOCK_STREAM = 1
            res = gdb.execute("""call socket(2, 1, 0)""", to_string=True)
            new_fd = self.get_fd_from_result(res)

            # fill in memory with sockaddr_in struct contents
            # we will do this in the stack, since connect() wants a pointer to a struct
            vmmap = get_process_maps()
            stack_addr = [entry.page_start for entry in vmmap if entry.path == "[stack]"][0]
            original_contents = read_memory(stack_addr, 8)

            '''
            struct sockaddr_in {
                short            sin_family;   // e.g. AF_INET
                unsigned short   sin_port;     // e.g. htons(3490)
                struct in_addr   sin_addr;     // see struct in_addr, below
                char             sin_zero[8];  // just padding
            };

            struct in_addr {
                unsigned long s_addr;  // load with inet_aton()
            };

            '''
            write_memory(stack_addr, "\x02\x00", 2)
            write_memory(stack_addr + 0x2, struct.pack("<H", socket.htons(port)), 2)
            write_memory(stack_addr + 0x4, socket.inet_aton(address), 4)

            info("Trying to connect to {}".format(new_output))
            # connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
            res = gdb.execute("""call connect({}, {}, {})""".format(new_fd, stack_addr, 16), to_string=True)

            # recover stack state
            write_memory(stack_addr, original_contents, 8)

            res = self.get_fd_from_result(res)
            if res == -1:
                err("Failed to connect to {}".format(addr))
                return

            info("Connected to {}".format(new_output))
        else:
            res = gdb.execute("""call open("{:s}", 66, 0666)""".format(new_output), to_string=True)
            new_fd = int(res.split()[2], 0)
        
        info("Opened '{:s}' as fd=#{:d}".format(new_output, new_fd))
        gdb.execute("""call dup2({:d}, {:d})""".format(new_fd, old_fd), to_string=True)
        info("Duplicated FD #{:d} {:s} #{:d}".format(old_fd, RIGHT_ARROW, new_fd))
        gdb.execute("""call close({:d})""".format(new_fd), to_string=True)
        ok("Success")
        enable_context()
        return

    def get_fd_from_result(self, res):
        # Output example: $1 = 3
        return int(res.split()[2], 0)


@register_command
class IdaInteractCommand(GenericCommand):
    """IDA Interact: set of commands to interact with IDA via a XML RPC service
    deployed via the IDA script `ida_gef.py`. It should be noted that this command
    can also be used to interact with Binary Ninja (using the script `binja_gef.py`)
    using the same interface."""

    _cmdline_ = "ida-interact"
    _syntax_  = "{:s} METHOD [ARGS]".format(_cmdline_)
    _aliases_ = ["binaryninja-interact", "bn", "binja"]
    _example_ = "\n{0:s} Jump $pc\n{0:s} SetColor $pc ff00ff".format(_cmdline_)

    def __init__(self):
        super(IdaInteractCommand, self).__init__(prefix=False)
        host, port = "127.0.0.1", 1337
        self.add_setting("host", host, "IP address to use connect to IDA/Binary Ninja script")
        self.add_setting("port", port, "Port to use connect to IDA/Binary Ninja script")
        self.add_setting("sync_cursor", False, "Enable real-time $pc synchronisation")

        self.sock = None
        self.version = ("", "")
        self.old_bps = set()
        return

    def is_target_alive(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.close()
        except socket.error:
            return False
        return True

    def connect(self, host=None, port=None):
        """Connect to the XML-RPC service."""
        host = host or self.get_setting("host")
        port = port or self.get_setting("port")

        try:
            sock = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(host, port))
            gef_on_stop_hook(ida_synchronize_handler)
            gef_on_continue_hook(ida_synchronize_handler)
            self.version = sock.version()
        except ConnectionRefusedError:
            err("Failed to connect to '{:s}:{:d}'".format(host, port))
            sock = None
        self.sock = sock
        return

    def disconnect(self):
        gef_on_stop_unhook(ida_synchronize_handler)
        gef_on_continue_unhook(ida_synchronize_handler)
        self.sock = None
        return

    def do_invoke(self, argv):
        def parsed_arglist(arglist):
            args = []
            for arg in arglist:
                try:
                    # try to solve the argument using gdb
                    argval = gdb.parse_and_eval(arg)
                    argval.fetch_lazy()
                    # check if value is addressable
                    argval = long(argval) if argval.address is None else long(argval.address)
                    # if the bin is PIE, we need to substract the base address
                    is_pie = checksec(get_filepath())["PIE"]
                    if is_pie and main_base_address <= argval < main_end_address:
                        argval -= main_base_address
                    args.append("{:#x}".format(argval,))
                except Exception:
                    # if gdb can't parse the value, let ida deal with it
                    args.append(arg)
            return args

        if self.sock is None:
            # trying to reconnect
            self.connect()
            if self.sock is None:
                self.disconnect()
                return

        if len(argv) == 0 or argv[0] in ("-h", "--help"):
            method_name = argv[1] if len(argv)>1 else None
            self.usage(method_name)
            return

        method_name = argv[0]
        if method_name == "version":
            self.version = self.sock.version()
            info("Enhancing {:s} with {:s} (v.{:s})".format(Color.greenify("gef"),
                                                            Color.redify(self.version[0]),
                                                            Color.yellowify(self.version[1])))
            return

        if not is_alive():
            main_base_address = main_end_address = 0
        else:
            vmmap = get_process_maps()
            main_base_address = min([x.page_start for x in vmmap if x.realpath == get_filepath()])
            main_end_address = max([x.page_end for x in vmmap if x.realpath == get_filepath()])

        try:
            if method_name == "Sync":
                self.synchronize()
            else:
                method = getattr(self.sock, method_name)
                if len(argv) > 1:
                    args = parsed_arglist(argv[1:])
                    res = method(*args)
                else:
                    res = method()

                if method_name in ("ImportStruct", "ImportStructs"):
                    self.import_structures(res)
                else:
                    gef_print(res)

            if self.get_setting("sync_cursor")==True:
                jump = getattr(self.sock, "Jump")
                jump(hex(current_arch.pc-main_base_address),)

        except socket.error:
            self.disconnect()
        return


    def synchronize(self):
        """Submit all active breakpoint addresses to IDA/BN"""
        pc = current_arch.pc
        vmmap = get_process_maps()
        base_address = min([x.page_start for x in vmmap if x.path == get_filepath()])
        end_address = max([x.page_end for x in vmmap if x.path == get_filepath()])
        if not (base_address <= pc < end_address):
            # do not sync in library
            return

        breakpoints = gdb.breakpoints() or []
        gdb_bps = set()
        for bp in breakpoints:
            if bp.enabled and not bp.temporary:
                if bp.location[0]=='*': # if it's an address i.e. location starts with '*'
                    addr = long(gdb.parse_and_eval(bp.location[1:]))
                else: # it is a symbol
                    addr = long(gdb.parse_and_eval(bp.location).address)
                if not (base_address <= addr < end_address):
                    continue
                gdb_bps.add(addr-base_address)

        added = gdb_bps - self.old_bps
        removed = self.old_bps - gdb_bps
        self.old_bps = gdb_bps

        try:
            # it is possible that the server was stopped between now and the last sync
            rc = self.sock.Sync("{:#x}".format(pc-base_address), list(added), list(removed))
        except ConnectionRefusedError:
            self.disconnect()
            return

        ida_added, ida_removed = rc

        # add new bp from IDA
        for new_bp in ida_added:
            location = base_address+new_bp
            gdb.Breakpoint("*{:#x}".format(location), type=gdb.BP_BREAKPOINT)
            self.old_bps.add(location)

        # and remove the old ones
        breakpoints = gdb.breakpoints() or []
        for bp in breakpoints:
            if bp.enabled and not bp.temporary:
                if bp.location[0]=='*': # if it's an address i.e. location starts with '*'
                    addr = long(gdb.parse_and_eval(bp.location[1:]))
                else: # it is a symbol
                    addr = long(gdb.parse_and_eval(bp.location).address)

                if not (base_address <= addr < end_address):
                    continue

                if (addr-base_address) in ida_removed:
                    if (addr-base_address) in self.old_bps:
                        self.old_bps.remove((addr-base_address))
                    bp.delete()
        return


    def usage(self, meth=None):
        if self.sock is None:
            return

        if meth is not None:
            gef_print(titlify(meth))
            gef_print(self.sock.system.methodHelp(meth))
            return

        info("Listing available methods and syntax examples: ")
        for m in self.sock.system.listMethods():
            if m.startswith("system."): continue
            gef_print(titlify(m))
            gef_print(self.sock.system.methodHelp(m))
        return


    def import_structures(self, structs):
        if self.version[0] != "IDA Pro":
            return

        path = get_gef_setting("pcustom.struct_path")
        if path is None:
            return

        if not os.path.isdir(path):
            gef_makedirs(path)

        for struct_name in structs:
            fullpath = os.path.join(path, "{}.py".format(struct_name))
            with open(fullpath, "wb") as f:
                f.write(b"from ctypes import *\n\n")
                f.write(b"class ")
                f.write(bytes(str(struct_name), encoding="utf-8"))
                f.write(b"(Structure):\n")
                f.write(b"    _fields_ = [\n")
                for _, name, size in structs[struct_name]:
                    name = bytes(name, encoding="utf-8")
                    if   size == 1: csize = b"c_uint8"
                    elif size == 2: csize = b"c_uint16"
                    elif size == 4: csize = b"c_uint32"
                    elif size == 8: csize = b"c_uint64"
                    else:           csize = b"c_byte * " + bytes(str(size), encoding="utf-8")
                    m = [b'        ("', name, b'", ', csize, b'),\n']
                    f.write(b"".join(m))
                f.write(b"]\n")
        ok("Success, {:d} structure{:s} imported".format(len(structs),
                                                         "s" if len(structs)>1 else ""))
        return


@register_command
class SearchPatternCommand(GenericCommand):
    """SearchPatternCommand: search a pattern in memory. If given an hex value (starting with 0x)
    the command will also try to look for upwards cross-references to this address."""

    _cmdline_ = "search-pattern"
    _syntax_  = "{:s} PATTERN [small|big]".format(_cmdline_)
    _aliases_ = ["grep", "xref"]
    _example_ = "\n{0:s} AAAAAAAA\n{0:s} 0x555555554000".format(_cmdline_)

    def search_pattern_by_address(self, pattern, start_address, end_address):
        """Search a pattern within a range defined by arguments."""
        pattern = gef_pybytes(pattern)
        step = 0x400 * 0x1000
        locations = []

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step

            mem = read_memory(chunk_addr, chunk_size)

            for match in re.finditer(pattern, mem):
                start = chunk_addr + match.start()
                try:
                    string = read_cstring_from_memory(start)
                    end   = start + len(string)
                except UnicodeError:
                    string = gef_pystring(pattern)+"[...]"
                    end    = start + len(pattern)
                locations.append((start, end, string))

            del mem

        return locations

    def search_pattern(self, pattern, endian):
        """Search a pattern within the whole userland memory."""
        if is_hex(pattern):
            if endian == Elf.BIG_ENDIAN:
                pattern = "".join(['\\x'+pattern[i:i+2] for i in range(2, len(pattern), 2)])
            else:
                pattern = "".join(['\\x'+pattern[i:i+2] for i in range(len(pattern)-2, 0, -2)])

        for section in get_process_maps():
            if not section.permission & Permission.READ: continue
            if section.path == "[vvar]": continue

            start = section.page_start
            end   = section.page_end - 1
            old_section = None

            for loc in self.search_pattern_by_address(pattern, start, end):
                addr_loc_start = lookup_address(loc[0])
                section = ""
                if addr_loc_start and addr_loc_start.section:
                    if old_section != addr_loc_start.section:
                        title = "In "
                        if addr_loc_start.section.path:
                            title += "'{}'".format(Color.blueify(addr_loc_start.section.path) )

                        title+= "({:#x}-{:#x})".format(addr_loc_start.section.page_start, addr_loc_start.section.page_end)
                        title+= ", permission={}".format(addr_loc_start.section.permission)
                        ok(title)
                        old_section = addr_loc_start.section

                gef_print("""  {:#x} - {:#x} {}  "{}" """.format(loc[0], loc[1], RIGHT_ARROW, Color.pinkify(loc[2]),))
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 1:
            self.usage()
            return

        pattern = argv[0]
        endian = get_endian()
        if argc==2:
            if argv[1]=="big": endian = Elf.BIG_ENDIAN
            elif argv[1]=="small": endian = Elf.LITTLE_ENDIAN

        info("Searching '{:s}' in memory".format(Color.yellowify(pattern)))
        self.search_pattern(pattern, endian)
        return


@register_command
class FlagsCommand(GenericCommand):
    """Edit flags in a human friendly way"""

    _cmdline_ = "edit-flags"
    _syntax_  = "{:s} [(+|-|~)FLAGNAME ...]".format(_cmdline_)
    _aliases_ = ["flags",]
    _example_ = "\n{0:s}\n{0:s} +zero # sets ZERO flag".format(_cmdline_)

    def do_invoke(self, argv):
        for flag in argv:
            if len(flag)<2:
                continue

            action = flag[0]
            name = flag[1:].lower()

            if action not in ("+", "-", "~"):
                err("Invalid action for flag '{:s}'".format(flag))
                continue

            if name not in current_arch.flags_table.values():
                err("Invalid flag name '{:s}'".format(flag[1:]))
                continue

            for k in current_arch.flags_table:
                if current_arch.flags_table[k] == name:
                    off = k
                    break

            old_flag = get_register(current_arch.flag_register)
            if action == "+":
                new_flags = old_flag | (1 << off)
            elif action == "-":
                new_flags = old_flag & ~(1 << off)
            else:
                new_flags = old_flag ^ (1<<off)

            gdb.execute("set ({:s}) = {:#x}".format(current_arch.flag_register, new_flags))

        gef_print(current_arch.flag_register_to_human())
        return


@register_command
class ChangePermissionCommand(GenericCommand):
    """Change a page permission. By default, it will change it to RWX."""

    _cmdline_ = "set-permission"
    _syntax_  = "{:s} LOCATION [PERMISSION]".format(_cmdline_)
    _aliases_ = ["mprotect",]
    _example_ = "{:s} $sp 7"

    def __init__(self):
        super(ChangePermissionCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def pre_load(self):
        try:
            __import__("keystone")
        except ImportError:
            msg = "Missing `keystone-engine` package for Python{0}, install with: `pip{0} install keystone-engine`.".format(PYTHON_MAJOR)
            raise ImportWarning(msg)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) not in (1, 2):
            err("Incorrect syntax")
            self.usage()
            return

        if len(argv) == 2:
            perm = int(argv[1])
        else:
            perm = Permission.READ | Permission.WRITE | Permission.EXECUTE

        loc = safe_parse_and_eval(argv[0])
        if loc is None:
            err("Invalid address")
            return

        loc = long(loc)
        sect = process_lookup_address(loc)
        if sect is None:
            err("Unmapped address")
            return

        size = sect.page_end - sect.page_start
        original_pc = current_arch.pc

        info("Generating sys_mprotect({:#x}, {:#x}, '{:s}') stub for arch {:s}"
             .format(sect.page_start, size, str(Permission(value=perm)), get_arch()))
        stub = self.get_stub_by_arch(sect.page_start, size, perm)
        if stub is None:
            err("Failed to generate mprotect opcodes")
            return

        info("Saving original code")
        original_code = read_memory(original_pc, len(stub))

        bp_loc = "*{:#x}".format(original_pc + len(stub))
        info("Setting a restore breakpoint at {:s}".format(bp_loc))
        ChangePermissionBreakpoint(bp_loc, original_code, original_pc)

        info("Overwriting current memory at {:#x} ({:d} bytes)".format(loc, len(stub)))
        write_memory(original_pc, stub, len(stub))

        info("Resuming execution")
        gdb.execute("continue")
        return

    def get_stub_by_arch(self, addr, size, perm):
        code = current_arch.mprotect_asm(addr, size, perm)
        arch, mode = get_keystone_arch()
        raw_insns = keystone_assemble(code, arch, mode, raw=True)
        return raw_insns


@register_command
class UnicornEmulateCommand(GenericCommand):
    """Use Unicorn-Engine to emulate the behavior of the binary, without affecting the GDB runtime.
    By default the command will emulate only the next instruction, but location and number of
    instruction can be changed via arguments to the command line. By default, it will emulate
    the next instruction from current PC."""

    _cmdline_ = "unicorn-emulate"
    _syntax_  = "{:s} [-f LOCATION] [-t LOCATION] [-n NB_INSTRUCTION] [-s] [-o PATH] [-h]".format(_cmdline_)
    _aliases_ = ["emulate",]
    _example_ = "{0:s} -f $pc -n 10 -o /tmp/my-gef-emulation.py".format(_cmdline_)

    def __init__(self):
        super(UnicornEmulateCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("verbose", False, "Set unicorn-engine in verbose mode")
        self.add_setting("show_disassembly", False, "Show every instruction executed")
        return

    def help(self):
        h = self._syntax_
        h += "\n\t-f LOCATION specifies the start address of the emulated run (default $pc).\n"
        h += "\t-t LOCATION specifies the end address of the emulated run.\n"
        h += "\t-s      Script-Only: do not execute the script once generated.\n"
        h += "\t-o /PATH/TO/SCRIPT.py writes the persistent Unicorn script into this file.\n"
        h += "\t-n NB_INSTRUCTION indicates the number of instructions to execute (mutually exclusive with `-t` and `-g`).\n"
        h += "\t-g NB_GADGET indicates the number of gadgets to execute (mutually exclusive with `-t` and `-n`).\n"
        h += "\nAdditional options can be setup via `gef config unicorn-emulate`\n"
        info(h)
        return

    def pre_load(self):
        try:
            __import__("unicorn")
        except ImportError:
            msg = "Missing `unicorn` package for Python{0}. Install with `pip{0} install unicorn`.".format(PYTHON_MAJOR)
            raise ImportWarning(msg)

        try:
            __import__("capstone")
        except ImportError:
            msg = "Missing `capstone` package for Python{0}. Install with `pip{0} install capstone`.".format(PYTHON_MAJOR)
            raise ImportWarning(msg)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        start_insn = None
        end_insn = -1
        nb_insn = -1
        to_file = None
        to_script_only = None
        opts = getopt.getopt(argv, "f:t:n:so:h")[0]
        for o,a in opts:
            if   o == "-f":   start_insn = int(a, 16)
            elif o == "-t":
                end_insn = int(a, 16)
                self.nb_insn = -1

            elif o == "-n":
                nb_insn = int(a)
                end_insn = -1

            elif o == "-s":
                to_script_only = True

            elif o == "-o":
                to_file = a

            elif o == "-h":
                self.help()
                return

        if start_insn is None:
            start_insn = current_arch.pc

        if end_insn < 0 and nb_insn < 0:
            err("No stop condition (-t|-n) defined.")
            return

        if end_insn > 0:
            self.run_unicorn(start_insn, end_insn, to_script_only=to_script_only, to_file=to_file)

        elif nb_insn > 0:
            end_insn = self.get_unicorn_end_addr(start_insn, nb_insn)
            self.run_unicorn(start_insn, end_insn, to_script_only=to_script_only, to_file=to_file)

        else:
            raise Exception("Should never be here")
        return

    def get_unicorn_end_addr(self, start_addr, nb):
        dis = list(gef_disassemble(start_addr, nb+1, True))
        last_insn = dis[-1]
        return last_insn.address

    def run_unicorn(self, start_insn_addr, end_insn_addr, *args, **kwargs):
        verbose = self.get_setting("verbose") or False
        to_script_only = kwargs.get("to_script_only", False)
        arch, mode = get_unicorn_arch(to_string=True)
        unicorn_registers = get_unicorn_registers(to_string=True)
        cs_arch, cs_mode = get_capstone_arch(to_string=True)
        fname = get_filename()
        to_file = kwargs.get("to_file", None)

        if to_file:
            tmp_filename = to_file
            to_file = open(to_file, "wb")
            tmp_fd = to_file.fileno()
        else:
            tmp_fd, tmp_filename = tempfile.mkstemp(suffix=".py", prefix="gef-uc-")

        if is_x86_32() or is_x86_64():
            # need to handle segmentation (and pagination) via MSR
            emulate_segmentation_block = """
# from https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_64_msr.py
SCRATCH_ADDR = 0xf000
SEGMENT_FS_ADDR = 0x5000
SEGMENT_GS_ADDR = 0x6000
FSMSR = 0xC0000100
GSMSR = 0xC0000101

def set_msr(uc, msr, value, scratch=SCRATCH_ADDR):
    buf = b'\\x0f\\x30'  # x86: wrmsr
    uc.mem_map(scratch, 0x1000)
    uc.mem_write(scratch, buf)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RAX, value & 0xFFFFFFFF)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(unicorn.x86_const.UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)
    uc.mem_unmap(scratch, 0x1000)
    return

def set_gs(uc, addr):    return set_msr(uc, GSMSR, addr)
def set_fs(uc, addr):    return set_msr(uc, FSMSR, addr)

"""

            context_segmentation_block = """
    emu.mem_map(SEGMENT_FS_ADDR-0x1000, 0x3000)
    set_fs(emu, SEGMENT_FS_ADDR)
    set_gs(emu, SEGMENT_GS_ADDR)
"""


        content = """#!/usr/bin/python -i
#
# Emulation script for '%s' from %#x to %#x
#
# Powered by gef, unicorn-engine, and capstone-engine
#
# @_hugsy_
#
from __future__ import print_function
import collections
import capstone, unicorn

registers = collections.OrderedDict(sorted({%s}.items(), key=lambda t: t[0]))
uc = None
verbose = %s
syscall_register = "%s"

def disassemble(code, addr):
    cs = capstone.Cs(%s, %s)
    for i in cs.disasm(str(code),addr):
        return i

def hook_code(emu, address, size, user_data):
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
    return

def code_hook(emu, address, size, user_data):
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
    return

def intr_hook(emu, intno, data):
    print(" \\-> interrupt={:d}".format(intno))
    return

def syscall_hook(emu, user_data):
    sysno = emu.reg_read(registers[syscall_register])
    print(" \\-> syscall={:d}".format(sysno))
    return

def print_regs(emu, regs):
    for i, r in enumerate(regs):
        print("{:7s} = 0x{:0%dx}  ".format(r, emu.reg_read(regs[r])), end="")
        if (i %% 4 == 3) or (i == len(regs)-1): print("")
    return

%s

def reset():
    emu = unicorn.Uc(%s, %s)

%s
""" % (fname, start_insn_addr, end_insn_addr,
       ",".join(["'%s': %s" % (k.strip(), unicorn_registers[k]) for k in unicorn_registers]),
       "True" if verbose else "False",
       current_arch.syscall_register,
       cs_arch, cs_mode,
       16 if is_elf64() else 8,
       emulate_segmentation_block if (is_x86_32() or is_x86_64() ) else "",
       arch, mode,
       context_segmentation_block if (is_x86_32() or is_x86_64() ) else "",
      )

        if verbose:
            info("Duplicating registers")

        for r in current_arch.all_registers:
            gregval = get_register(r)
            content += "    emu.reg_write(%s, %#x)\n" % (unicorn_registers[r], gregval)


        vmmap = get_process_maps()
        if not vmmap:
            warn("An error occured when reading memory map.")
            return

        if verbose:
            info("Duplicating memory map")

        for sect in vmmap:
            if sect.path == "[vvar]":
                # this section is for GDB only, skip it
                continue

            page_start = sect.page_start
            page_end   = sect.page_end
            size       = sect.size
            perm       = sect.permission

            content += "    # Mapping %s: %#x-%#x\n" % (sect.path, page_start, page_end)
            content += "    emu.mem_map(%#x, %#x, %s)\n" % (page_start, size, oct(perm.value))

            if perm & Permission.READ:
                code = read_memory(page_start, size)
                loc = "/tmp/gef-%s-%#x.raw" % (fname, page_start)
                with open(loc, "wb") as f:
                    f.write(bytes(code))

                content += "    emu.mem_write(%#x, open('%s', 'rb').read())\n" % (page_start, loc)
                content += "\n"


        content += "    emu.hook_add(unicorn.UC_HOOK_CODE, code_hook)\n"
        content += "    emu.hook_add(unicorn.UC_HOOK_INTR, intr_hook)\n"
        if is_x86_64():
            content += "    emu.hook_add(unicorn.UC_HOOK_INSN, syscall_hook, None, 1, 0, unicorn.x86_const.UC_X86_INS_SYSCALL)\n"
        content += "    return emu\n"

        content += """
def emulate(emu, start_addr, end_addr):
    print("========================= Initial registers =========================")
    print_regs(emu, registers)

    try:
        print("========================= Starting emulation =========================")
        emu.emu_start(start_addr, end_addr)
    except Exception as e:
        emu.emu_stop()
        print("========================= Emulation failed =========================")
        print("[!] Error: {}".format(e))

    print("========================= Final registers =========================")
    print_regs(emu, registers)
    return


uc = reset()
emulate(uc, %#x, %#x)

# unicorn-engine script generated by gef
""" % (start_insn_addr, end_insn_addr)

        os.write(tmp_fd, gef_pybytes(content))
        os.close(tmp_fd)

        if kwargs.get("to_file", None):
            info("Unicorn script generated as '%s'" % tmp_filename)
            os.chmod(tmp_filename, 0o700)

        if to_script_only:
            return

        ok("Starting emulation: %#x %s %#x" % (start_insn_addr, RIGHT_ARROW, end_insn_addr))

        res = gef_execute_external(["python", tmp_filename], as_list=True)
        gef_print("\n".join(res))

        if not kwargs.get("to_file", None):
            os.unlink(tmp_filename)
        return


@register_command
class RemoteCommand(GenericCommand):
    """gef wrapper for the `target remote` command. This command will automatically
    download the target binary in the local temporary directory (defaut /tmp) and then
    source it. Additionally, it will fetch all the /proc/PID/maps and loads all its
    information."""

    _cmdline_ = "gef-remote"
    _syntax_  = "{:s} [OPTIONS] TARGET".format(_cmdline_)
    _example_  = "\n{0:s} -p 6789 localhost:1234\n{0:s} -q localhost:4444 # when using qemu-user".format(_cmdline_)

    def __init__(self):
        super(RemoteCommand, self).__init__(prefix=False)
        self.handler_connected = False
        self.add_setting("clean_on_exit", False, "Clean the temporary data downloaded when the session exits.")
        return

    def do_invoke(self, argv):
        global __gef_remote__

        if __gef_remote__ is not None:
            err("You already are in remote session. Close it first before opening a new one...")
            return

        target = None
        rpid = -1
        update_solib = False
        self.download_all_libs = False
        download_lib = None
        is_extended_remote = False
        qemu_gdb_mode = False
        opts, args = getopt.getopt(argv, "p:UD:qAEh")
        for o,a in opts:
            if   o == "-U":   update_solib = True
            elif o == "-D":   download_lib = a
            elif o == "-A":   self.download_all_libs = True
            elif o == "-E":   is_extended_remote = True
            elif o == "-p":   rpid = int(a)
            elif o == "-q":   qemu_gdb_mode = True
            elif o == "-h":
                self.help()
                return

        if not args or ':' not in args[0]:
            err("A target (HOST:PORT) must always be provided.")
            return

        if qemu_gdb_mode:
            # compat layer for qemu-user
            self.prepare_qemu_stub(args[0])
            return

        # lazily install handler on first use
        if not self.handler_connected:
            gef_on_new_hook(self.new_objfile_handler)
            self.handler_connected = True

        target = args[0]

        if self.connect_target(target, is_extended_remote) == False:
            return

        # if extended-remote, need to attach
        if is_extended_remote:
            ok("Attaching to {:d}".format(rpid))
            disable_context()
            gdb.execute("attach {:d}".format(rpid))
            enable_context()
        else:
            rpid = get_pid()
            ok("Targeting PID={:d}".format(rpid))

        self.add_setting("target", target, "Remote target to connect to")
        self.setup_remote_environment(rpid, update_solib)

        if not is_remote_debug():
            err("Failed to establish remote target environment.")
            return

        if self.download_all_libs == True:
            vmmap = get_process_maps()
            success = 0
            for sect in vmmap:
                if sect.path.startswith("/"):
                    _file = download_file(sect.path)
                    if _file is None:
                        err("Failed to download {:s}".format(sect.path))
                    else:
                        success += 1

            ok("Downloaded {:d} files".format(success))

        elif download_lib is not None:
            _file = download_file(download_lib)
            if _file is None:
                err("Failed to download remote file")
                return

            ok("Download success: {:s} {:s} {:s}".format(download_lib, RIGHT_ARROW, _file))

        if update_solib:
            self.refresh_shared_library_path()

        set_arch()
        __gef_remote__ = rpid
        return

    def new_objfile_handler(self, event):
        """Hook that handles new_objfile events, will update remote environment accordingly"""
        if not is_remote_debug():
            return

        if self.download_all_libs and event.new_objfile.filename.startswith("target:"):
            lib = event.new_objfile.filename[len("target:"):]
            llib = download_file(lib, use_cache=True)
            if llib:
                ok("Download success: {:s} {:s} {:s}".format(lib, RIGHT_ARROW, llib))
        return


    def setup_remote_environment(self, pid, update_solib=False):
        """Clone the remote environment locally in the temporary directory.
        The command will duplicate the entries in the /proc/<pid> locally and then
        source those information into the current gdb context to allow gef to use
        all the extra commands as it was local debugging."""
        gdb.execute("reset-cache")

        infos = {}
        for i in ("maps", "environ", "cmdline",):
            infos[i] = self.load_from_remote_proc(pid, i)
            if infos[i] is None:
                err("Failed to load memory map of '{:s}'".format(i))
                return

        exepath = get_path_from_info_proc()
        infos["exe"] = download_file("/proc/{:d}/exe".format(pid), use_cache=False, local_name=exepath)
        if not os.access(infos["exe"], os.R_OK):
            err("Source binary is not readable")
            return

        directory  = os.path.sep.join([GEF_TEMP_DIR, str(get_pid())])
        # gdb.execute("file {:s}".format(infos["exe"]))
        self.add_setting("root", directory, "Path to store the remote data")
        ok("Remote information loaded to temporary path '{:s}'".format(directory))
        return


    def connect_target(self, target, is_extended_remote):
        """Connect to remote target and get symbols. To prevent `gef` from requesting information
        not fetched just yet, we disable the context disable when connection was successful."""
        disable_context()
        try:
            cmd = "target {} {}".format("extended-remote" if is_extended_remote else "remote", target)
            gdb.execute(cmd)
            ok("Connected to '{}'".format(target))
            ret = True
        except Exception as e:
            err("Failed to connect to {:s}: {:s}".format(target, str(e)))
            ret = False
        enable_context()
        return ret


    def load_from_remote_proc(self, pid, info):
        """Download one item from /proc/pid"""
        remote_name = "/proc/{:d}/{:s}".format(pid, info)
        return download_file(remote_name, use_cache=False)


    def refresh_shared_library_path(self):
        dirs = [r for r, d, f in os.walk(self.get_setting("root"))]
        path = ":".join(dirs)
        gdb.execute("set solib-search-path {:s}".format(path,))
        return


    def help(self):
        h = self._syntax_
        h += "\n\t   TARGET (mandatory) specifies the host:port, serial port or tty to connect to.\n"
        h += "\t-U will update gdb `solib-search-path` attribute to include the files downloaded from server (default: False).\n"
        h += "\t-A will download *ALL* the remote shared libraries and store them in the new environment. " \
             "This command can take a few minutes to complete (default: False).\n"
        h += "\t-D LIB will download the remote library called LIB.\n"
        h += "\t-E Use 'extended-remote' to connect to the target.\n"
        h += "\t-p PID (mandatory if -E is used) specifies PID of the debugged process on gdbserver's end.\n"
        h += "\t-q Uses this option when connecting to a Qemu GDBserver.\n"
        info(h)
        return


    def prepare_qemu_stub(self, target):
        global current_arch, current_elf, __gef_qemu_mode__

        reset_all_caches()
        arch = get_arch()
        current_elf  = Elf(minimalist=True)
        if   arch.startswith("arm"):
            current_elf.e_machine = Elf.ARM
            current_arch = ARM()
        elif arch.startswith("aarch64"):
            current_elf.e_machine = Elf.AARCH64
            current_arch = AARCH64()
        elif arch.startswith("i386:intel"):
            current_elf.e_machine = Elf.X86_32
            current_arch = X86()
        elif arch.startswith("i386:x86-64"):
            current_elf.e_machine = Elf.X86_64
            current_elf.e_class = Elf.ELF_64_BITS
            current_arch = X86_64()
        elif arch.startswith("mips"):
            current_elf.e_machine = Elf.MIPS
            current_arch = MIPS()
        elif arch.startswith("powerpc"):
            current_elf.e_machine = Elf.POWERPC
            current_arch = PowerPC()
        elif arch.startswith("sparc"):
            current_elf.e_machine = Elf.SPARC
            current_arch = SPARC()
        else:
            raise RuntimeError("unsupported architecture: {}".format(arch))

        ok("Setting QEMU-stub for '{}' (memory mapping may be wrong)".format(current_arch.arch))
        gdb.execute("target remote {}".format(target))
        __gef_qemu_mode__ = True
        return


@register_command
class NopCommand(GenericCommand):
    """Patch the instruction(s) pointed by parameters with NOP. Note: this command is architecture
    aware."""

    _cmdline_ = "nop"
    _syntax_  = "{:s} [-b NUM_BYTES] [-h] [LOCATION]".format(_cmdline_)
    _example_ = "{:s} $pc".format(_cmdline_)

    def __init__(self):
        super(NopCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return


    def get_insn_size(self, addr):
        cur_insn = gef_current_instruction(addr)
        next_insn = gef_instruction_n(addr, 2)
        return next_insn.address - cur_insn.address


    def do_invoke(self, argv):
        opts, args = getopt.getopt(argv, "b:h")
        num_bytes = 0
        for o, a in opts:
            if o == "-b":
                num_bytes = long(a, 0)
            elif o == "-h":
                self.help()
                return

        if args:
            loc = parse_address(args[0])
        else:
            loc = current_arch.pc

        self.nop_bytes(loc, num_bytes)
        return


    def help(self):
        m = self._syntax_
        m += "\n  LOCATION\taddress/symbol to patch\n"
        m += "  -b NUM_BYTES\tInstead of writing one instruction, patch the specified number of bytes\n"
        m += "  -h \t\tprint this help\n"
        info(m)
        return

    @only_if_gdb_running
    def nop_bytes(self, loc, num_bytes):
        if num_bytes == 0:
            size = self.get_insn_size(loc)
        else:
            size = num_bytes
        nops = current_arch.nop_insn

        if len(nops) > size:
            m = "Cannot patch instruction at {:#x} (nop_size is:{:d},insn_size is:{:d})".format(loc, len(nops), size)
            err(m)
            return

        while len(nops) < size:
            nops += current_arch.nop_insn

        if len(nops) != size:
            err("Cannot patch instruction at {:#x} (nop instruction does not evenly fit in requested size)"
                .format(loc))
            return

        ok("Patching {:d} bytes from {:s}".format(size, format_address(loc)))
        write_memory(loc, nops, size)

        return


@register_command
class StubCommand(GenericCommand):
    """Stub out the specified function. This function is useful when needing to skip one
    function to be called and disrupt your runtime flow (ex. fork)."""

    _cmdline_ = "stub"
    _syntax_  = """{:s} [-r RETVAL] [-h] [LOCATION]
\tLOCATION\taddress/symbol to stub out
\t-r RETVAL\tSet the return value""".format(_cmdline_)
    _example_ = "{:s} -r 0 fork"

    def __init__(self):
        super(StubCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        try:
            opts, args = getopt.getopt(argv, "r:")
            retval = 0
            for o, a in opts:
                if o == "-r":
                    retval = long(a, 0)
        except getopt.GetoptError:
            self.usage()
            return

        loc = args[0] if args else "*{:#x}".format(current_arch.pc)
        StubBreakpoint(loc, retval)
        return


@register_command
class CapstoneDisassembleCommand(GenericCommand):
    """Use capstone disassembly framework to disassemble code."""

    _cmdline_ = "capstone-disassemble"
    _syntax_  = "{:s} [LOCATION] [[length=LENGTH] [option=VALUE]] ".format(_cmdline_)
    _aliases_ = ["cs-dis",]
    _example_ = "{:s} $pc length=50".format(_cmdline_)

    def pre_load(self):
        try:
            __import__("capstone")
        except ImportError:
            msg = "Missing `capstone` package for Python{0}. Install with `pip{0} install capstone`.".format(PYTHON_MAJOR)
            raise ImportWarning(msg)
        return

    def __init__(self):
        super(CapstoneDisassembleCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        location = None

        kwargs = {}
        for arg in argv:
            if '=' in arg:
                key, value = arg.split('=', 1)
                kwargs[key] = value

            elif location is None:
                location = parse_address(arg)

        location = location or current_arch.pc
        length = int(kwargs.get("length", get_gef_setting("context.nb_lines_code")))

        for insn in capstone_disassemble(location, length, **kwargs):
            text_insn = str(insn)
            msg = ""

            if insn.address == current_arch.pc:
                msg = Color.colorify("{}   {}".format(RIGHT_ARROW, text_insn), attrs="bold red")
                reason = self.capstone_analyze_pc(insn, length)[0]
                if reason:
                    gef_print(msg)
                    gef_print(reason)
                    break
            else:
                msg = "{} {}".format(" "*5, text_insn)

            gef_print(msg)
        return

    def capstone_analyze_pc(self, insn, nb_insn):
        if current_arch.is_conditional_branch(insn):
            is_taken, reason = current_arch.is_branch_taken(insn)
            if is_taken:
                reason = "[Reason: {:s}]".format(reason) if reason else ""
                msg = Color.colorify("\tTAKEN {:s}".format(reason), attrs="bold green")
            else:
                reason = "[Reason: !({:s})]".format(reason) if reason else ""
                msg = Color.colorify("\tNOT taken {:s}".format(reason), attrs="bold red")
            return (is_taken, msg)

        if current_arch.is_call(insn):
            target_address = int(insn.operands[-1].split()[0], 16)
            msg = []
            for i, new_insn in enumerate(capstone_disassemble(target_address, nb_insn)):
                msg.append("   {}  {}".format (DOWN_ARROW if i==0 else " ", str(new_insn)))
            return (True, "\n".join(msg))

        return (False, "")


@register_command
class GlibcHeapCommand(GenericCommand):
    """Base command to get information about the Glibc heap structure."""

    _cmdline_ = "heap"
    _syntax_  = "{:s} (chunk|chunks|bins|arenas)".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapCommand, self).__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.usage()
        return


@register_command
class GlibcHeapSetArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap set-arena"
    _syntax_  = "{:s} LOCATION".format(_cmdline_)
    _example_ = "{:s} 0x001337001337".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapSetArenaCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __gef_default_main_arena__

        if len(argv) < 1:
            ok("Current main_arena set to: '{}'".format(__gef_default_main_arena__))
            return

        new_arena = safe_parse_and_eval(argv[0])
        if new_arena is None:
            err("Invalid location")
            return

        if argv[0].startswith("0x"):
            new_arena = Address(to_unsigned_long(new_arena))
            if new_arena is None or not new_arena.valid:
                err("Invalid location")
                return

            __gef_default_main_arena__ = "*{:s}".format(format_address(new_arena.value))
        else:
            __gef_default_main_arena__ = argv[0]
        return

@register_command
class GlibcHeapArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap arenas"
    _syntax_  = _cmdline_

    @only_if_gdb_running
    def do_invoke(self, argv):
        try:
            arena = GlibcArena(__gef_default_main_arena__)
        except gdb.error:
            err("Could not find Glibc main arena")
            return

        while True:
            gef_print("{}".format(arena))
            arena = arena.get_next()
            if arena is None:
                break
        return

@register_command
class GlibcHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk.
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _cmdline_ = "heap chunk"
    _syntax_  = "{:s} LOCATION".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapChunkCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) < 1:
            err("Missing chunk address")
            self.usage()
            return

        if get_main_arena() is None:
            return

        addr = to_unsigned_long(gdb.parse_and_eval(argv[0]))
        chunk = GlibcChunk(addr)
        chunk.pprint()
        return

@register_command
class GlibcHeapChunksCommand(GenericCommand):
    """Display information all chunks from main_arena heap. If a location is passed,
    it must correspond to the base address of the first chunk."""

    _cmdline_ = "heap chunks"
    _syntax_  = "{0} [LOCATION]".format(_cmdline_)
    _example_ = "\n{0}\n{0} 0x555555775000".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapChunksCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("peek_nb_byte", 16, "Hexdump N first byte(s) inside the chunk data (0 to disable)")
        return

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not argv:
            heap_section = [x for x in get_process_maps() if x.path == "[heap]"]
            if not heap_section:
                err("No heap section")
                return

            heap_section = heap_section[0].page_start
        else:
            heap_section = int(argv[0], 0)


        arena = get_main_arena()
        if arena is None:
            err("No valid arena")
            return

        nb = self.get_setting("peek_nb_byte")
        current_chunk = GlibcChunk(heap_section, from_base=True)
        while True:

            if current_chunk.chunk_base_address == arena.top:
                gef_print("{} {} {}".format(str(current_chunk), LEFT_ARROW, Color.greenify("top chunk")))
                break

            if current_chunk.chunk_base_address > arena.top:
                break

            if current_chunk.size == 0:
                # EOF
                break

            line = str(current_chunk)
            if nb:
                line += "\n    [" + hexdump(read_memory(current_chunk.address, nb), nb, base=current_chunk.address)  + "]"
            gef_print(line)

            next_chunk = current_chunk.get_next_chunk()
            if next_chunk is None:
                break

            next_chunk_addr = Address(next_chunk.address)
            if not next_chunk_addr.valid:
                # corrupted
                break


            current_chunk = next_chunk
        return

@register_command
class GlibcHeapBinsCommand(GenericCommand):
    """Display information on the bins on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _bin_types_ = ["fast", "unsorted", "small", "large"]
    _cmdline_ = "heap bins"
    _syntax_ = "{:s} [{:s}]".format(_cmdline_, "|".join(_bin_types_))

    def __init__(self):
        super(GlibcHeapBinsCommand, self).__init__(prefix=True, complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) == 0:
            for bin_t in GlibcHeapBinsCommand._bin_types_:
                gdb.execute("heap bins {:s}".format(bin_t))
            return

        bin_t = argv[0]
        if bin_t not in GlibcHeapBinsCommand._bin_types_:
            self.usage()
            return

        gdb.execute("heap bins {}".format(bin_t))
        return

    @staticmethod
    def pprint_bin(arena_addr, index, _type=""):
        arena = GlibcArena(arena_addr)
        fw, bk = arena.bin(index)

        if bk==0x00 and fw==0x00:
            warn("Invalid backward and forward bin pointers(fw==bk==NULL)")
            return -1

        nb_chunk = 0
        if bk == fw and ((int(arena)&~0xFFFF) == (bk&~0xFFFF)):
            return nb_chunk

        ok("{}bins[{:d}]: fw={:#x}, bk={:#x}".format(_type, index, fw, bk))

        m = []
        head = GlibcChunk(bk, from_base=True).fwd
        while fw != head:
            chunk = GlibcChunk(fw, from_base=True)
            m.append("{:s}  {:s}".format(RIGHT_ARROW, str(chunk)))
            fw = chunk.fwd
            nb_chunk += 1

        gef_print("  ".join(m))
        return nb_chunk

@register_command
class GlibcHeapFastbinsYCommand(GenericCommand):
    """Display information on the fastbinsY on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _cmdline_ = "heap bins fast"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapFastbinsYCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        def fastbin_index(sz):
            return (sz >> 4) - 2 if SIZE_SZ == 8 else (sz >> 3) - 2

        SIZE_SZ = current_arch.ptrsize
        MAX_FAST_SIZE = (80 * SIZE_SZ // 4)
        NFASTBINS = fastbin_index(MAX_FAST_SIZE) - 1

        arena = GlibcArena("*{:s}".format(argv[0])) if len(argv) == 1 else get_main_arena()

        if arena is None:
            err("Invalid Glibc arena")
            return

        gef_print(titlify("Fastbins for arena {:#x}".format(int(arena))))
        for i in range(NFASTBINS):
            gef_print("Fastbins[idx={:d}, size={:#x}] ".format(i, (i+1)*SIZE_SZ*2), end="")
            chunk = arena.fastbin(i)
            chunks = []

            while True:
                if chunk is None:
                    gef_print("0x00", end="")
                    break

                try:
                    gef_print("{:s} {:s} ".format(LEFT_ARROW, str(chunk)), end="")
                    if chunk.address in chunks:
                        gef_print("{:s} [loop detected]".format(RIGHT_ARROW), end="")
                        break

                    if fastbin_index(chunk.get_chunk_size()) != i:
                        gef_print("[incorrect fastbin_index] ", end="")

                    chunks.append(chunk.address)

                    next_chunk = chunk.get_fwd_ptr()
                    if next_chunk == 0:
                        break

                    chunk = GlibcChunk(next_chunk, from_base=True)
                except gdb.MemoryError:
                    gef_print("{:s} [Corrupted chunk at {:#x}]".format(LEFT_ARROW, chunk.address), end="")
                    break
            gef_print()
        return

@register_command
class GlibcHeapUnsortedBinsCommand(GenericCommand):
    """Display information on the Unsorted Bins of an arena (default: main_arena).
    See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689"""

    _cmdline_ = "heap bins unsorted"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapUnsortedBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if get_main_arena() is None:
            err("Invalid Glibc arena")
            return

        arena_addr = "*{:s}".format(argv[0]) if len(argv) == 1 else "main_arena"
        gef_print(titlify("Unsorted Bin for arena '{:s}'".format(arena_addr)))
        nb_chunk = GlibcHeapBinsCommand.pprint_bin(arena_addr, 0, "unsorted_")
        if nb_chunk >= 0:
            info("Found {:d} chunks in unsorted bin.".format(nb_chunk))
        return

@register_command
class GlibcHeapSmallBinsCommand(GenericCommand):
    """Convenience command for viewing small bins."""

    _cmdline_ = "heap bins small"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapSmallBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if get_main_arena() is None:
            err("Invalid Glibc arena")
            return

        arena_addr = "*{:s}".format(argv[0]) if len(argv) == 1 else "main_arena"
        gef_print(titlify("Small Bins for arena '{:s}'".format(arena_addr)))
        bins = {}
        for i in range(1, 63):
            nb_chunk = GlibcHeapBinsCommand.pprint_bin(arena_addr, i, "small_")
            if nb_chunk < 0:
                break
            if nb_chunk > 0:
                bins[i] = nb_chunk
        info("Found {:d} chunks in {:d} small non-empty bins.".format(sum(bins.values()), len(bins)))
        return

@register_command
class GlibcHeapLargeBinsCommand(GenericCommand):
    """Convenience command for viewing large bins."""

    _cmdline_ = "heap bins large"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapLargeBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if get_main_arena() is None:
            err("Invalid Glibc arena")
            return

        arena_addr = "*{:s}".format(argv[0]) if len(argv) == 1 else "main_arena"
        gef_print(titlify("Large Bins for arena '{:s}'".format(arena_addr)))
        bins = {}
        for i in range(63, 126):
            nb_chunk = GlibcHeapBinsCommand.pprint_bin(arena_addr, i, "large_")
            if nb_chunk < 0:
                break
            if nb_chunk > 0:
                bins[i] = nb_chunk
        info("Found {:d} chunks in {:d} large non-empty bins.".format(sum(bins.values()), len(bins)))
        return


@register_command
class SolveKernelSymbolCommand(GenericCommand):
    """Solve kernel symbols from kallsyms table."""

    _cmdline_ = "ksymaddr"
    _syntax_  = "{:s} SymbolToSearch".format(_cmdline_)
    _example_ = "{:s} prepare_creds".format(_cmdline_)

    def do_invoke(self, argv):
        if len(argv) != 1:
            self.usage()
            return

        found = False
        sym = argv[0]
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                try:
                    symaddr, symtype, symname = line.strip().split(" ", 3)
                    symaddr = long(symaddr, 16)
                    if symname == sym:
                        ok("Found matching symbol for '{:s}' at {:#x} (type={:s})".format(sym, symaddr, symtype))
                        found = True
                    if sym in symname:
                        warn("Found partial match for '{:s}' at {:#x} (type={:s}): {:s}".format(sym, symaddr, symtype, symname))
                        found = True
                except ValueError:
                    pass

        if not found:
            err("No match for '{:s}'".format(sym))
        return


@register_command
class DetailRegistersCommand(GenericCommand):
    """Display full details on one, many or all registers value from current architecture."""

    _cmdline_ = "registers"
    _syntax_  = "{:s} [[Register1][Register2] ... [RegisterN]]".format(_cmdline_)
    _example_ = "\n{0:s}\n{0:s} $eax $eip $esp".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        regs = []
        regname_color = get_gef_setting("theme.registers_register_name")
        changed_register_value_color = get_gef_setting("theme.registers_value_changed")
        string_color = get_gef_setting("theme.dereference_string")

        if argv:
            regs = [reg for reg in current_arch.all_registers if reg.strip() in argv]
        else:
            regs = current_arch.all_registers

        memsize = current_arch.ptrsize
        endian = endian_str()
        charset = string.printable

        for regname in regs:
            reg = gdb.parse_and_eval(regname)
            if reg.type.code == gdb.TYPE_CODE_VOID:
                continue

            if ( is_x86_64() or is_x86_32() ) and regname in current_arch.msr_registers:
                msr = set(current_arch.msr_registers)
                for r in set(regs) & msr:
                    line = "{}: ".format( Color.colorify(r.strip(), attrs=regname_color) )
                    line+= "0x{:04x}".format(get_register(r))
                    gef_print(line, end="  ")
                    regs.remove(r)
                gef_print()
                continue

            line = "{}: ".format( Color.colorify(regname, attrs=regname_color) )

            if str(reg) == "<unavailable>":
                line += Color.colorify("no value", attrs="yellow underline")
                gef_print(line)
                continue

            if regname.strip() == current_arch.flag_register:
                line += current_arch.flag_register_to_human()
                gef_print(line)
                continue

            old_value = ContextCommand.old_registers.get(regname, 0)
            new_value = align_address(long(reg))
            if new_value == old_value:
                line += format_address_spaces(new_value)
            else:
                line += Color.colorify(format_address_spaces(new_value), attrs=changed_register_value_color)
            addrs = DereferenceCommand.dereference_from(new_value)

            if len(addrs) > 1:
                sep = " {:s} ".format(RIGHT_ARROW)
                line += sep
                line += sep.join(addrs[1:])

            # check to see if reg value is ascii
            try:
                fmt = "{}{}".format(endian, "I" if memsize==4 else "Q")
                last_addr = int(addrs[-1],16)
                val = gef_pystring(struct.pack(fmt, last_addr))
                if all([_ in charset for _ in val]):
                    line += ' ("{:s}"?)'.format( Color.colorify(val, attrs=string_color) )
            except ValueError:
                pass

            gef_print(line)
        return


@register_command
class ShellcodeCommand(GenericCommand):
    """ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to
    download shellcodes."""

    _cmdline_ = "shellcode"
    _syntax_  = "{:s} <search|get>".format(_cmdline_)

    def __init__(self):
        super(ShellcodeCommand, self).__init__(prefix=True)
        return

    def do_invoke(self, argv):
        err("Missing sub-command <search|get>")
        self.usage()
        return


@register_command
class ShellcodeSearchCommand(GenericCommand):
    """Search pattern in shell-storm's shellcode database."""

    _cmdline_ = "shellcode search"
    _syntax_  = "{:s} <pattern1> <pattern2>".format(_cmdline_)
    _aliases_ = ["sc-search",]

    api_base = "http://shell-storm.org"
    search_url = "{}/api/?s=".format(api_base)


    def do_invoke(self, argv):
        if not argv:
            err("Missing pattern to search")
            self.usage()
            return

        self.search_shellcode(argv)
        return


    def search_shellcode(self, search_options):
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

@register_command
class ShellcodeGetCommand(GenericCommand):
    """Download shellcode from shell-storm's shellcode database."""

    _cmdline_ = "shellcode get"
    _syntax_  = "{:s} <shellcode_id>".format(_cmdline_)
    _aliases_ = ["sc-get",]

    api_base = "http://shell-storm.org"
    get_url = "{}/shellcode/files/shellcode-{{:d}}.php".format(api_base)

    def do_invoke(self, argv):
        if len(argv) != 1:
            err("Missing ID to download")
            self.usage()
            return

        if not argv[0].isdigit():
            err("ID is not a number")
            self.usage()
            return

        self.get_shellcode(long(argv[0]))
        return

    def get_shellcode(self, sid):
        res = http_get(self.get_url.format(sid))
        if res is None:
            err("Failed to fetch shellcode #{:d}".format(sid))
            return

        ret  = gef_pystring(res)

        info("Downloading shellcode id={:d}".format(sid))
        fd, fname = tempfile.mkstemp(suffix=".txt", prefix="sc-", text=True, dir="/tmp")
        data = ret.split("\\n")[7:-11]
        buf = "\n".join(data)
        buf = HTMLParser().unescape(buf)
        os.write(fd, gef_pybytes(buf))
        os.close(fd)
        info("Shellcode written to '{:s}'".format(fname))
        return


@register_command
class RopperCommand(GenericCommand):
    """Ropper (http://scoding.de/ropper) plugin"""

    _cmdline_ = "ropper"
    _syntax_  = "{:s} [ROPPER_OPTIONS]".format(_cmdline_)

    def __init__(self):
        super(RopperCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        return

    def pre_load(self):
        try:
            __import__("ropper")
        except ImportError:
            msg = "Missing `ropper` package for Python{0}, install with: `pip{0} install ropper`.".format(PYTHON_MAJOR)
            raise ImportWarning(msg)
        return


    @only_if_gdb_running
    def do_invoke(self, argv):
        ropper = sys.modules["ropper"]
        if "--file" not in argv:
            path = get_filepath()
            sect = next( filter(lambda x: x.path == path, get_process_maps()) )
            argv.append("--file")
            argv.append(path)
            argv.append("-I")
            argv.append("{:#x}".format(sect.page_start))

        import readline
        # ropper set up own autocompleter after which gdb/gef autocomplete don't work
        old_completer_delims = readline.get_completer_delims()
        old_completer = readline.get_completer()
        ropper.start(argv)
        readline.set_completer(old_completer)
        readline.set_completer_delims(old_completer_delims)
        return


@register_command
class AssembleCommand(GenericCommand):
    """Inline code assemble. Architecture can be set in GEF runtime config (default x86-32). """

    _cmdline_ = "assemble"
    _syntax_  = "{:s} [-a ARCH] [-m MODE] [-e] [-s] [-l LOCATION] instruction;[instruction;...instruction;])".format(_cmdline_)
    _aliases_ = ["asm",]
    _example_ = "\n{0:s} -a x86 -m 32 nop ; nop ; inc eax ; int3\n{0:s} -a arm -m arm add r0, r0, 1".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(AssembleCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.valid_arch_modes = {
            "ARM" : ["ARM", "THUMB"],
            "ARM64" : ["ARM", "THUMB", "V5", "V8", ],
            "MIPS" : ["MICRO", "MIPS3", "MIPS32", "MIPS32R6", "MIPS64",],
            "PPC" : ["PPC32", "PPC64", "QPX",],
            "SPARC" : ["SPARC32", "SPARC64", "V9",],
            "SYSTEMZ" : ["32",],
            "X86" : ["16", "32", "64"],
        }
        return

    def pre_load(self):
        try:
            __import__("keystone")
        except ImportError:
            msg = "Missing `keystone-engine` package for Python{0}, install with: `pip{0} install keystone-engine`.".format(PYTHON_MAJOR)
            raise ImportWarning(msg)
        return

    def usage(self):
        super(AssembleCommand, self).usage()
        gef_print("\nAvailable architectures/modes:")
        # for updates, see https://github.com/keystone-engine/keystone/blob/master/include/keystone/keystone.h
        for arch in self.valid_arch_modes:
            gef_print(" - {} ".format(arch))
            gef_print("  * {}".format( " / ".join(self.valid_arch_modes[arch]) ))
        return

    def do_invoke(self, argv):
        arch_s, mode_s, big_endian, as_shellcode, write_to_location = None, None, False, False, None
        opts, args = getopt.getopt(argv, "a:m:l:esh")
        for o,a in opts:
            if o == "-a": arch_s = a.upper()
            if o == "-m": mode_s = a.upper()
            if o == "-e": big_endian = True
            if o == "-s": as_shellcode = True
            if o == "-l": write_to_location = long(gdb.parse_and_eval(a))
            if o == "-h":
                self.usage()
                return

        if not args:
            return

        if (arch_s, mode_s) == (None, None):
            if is_alive():
                arch_s, mode_s = current_arch.arch, current_arch.mode
                endian_s = "big" if is_big_endian() else "little"
                arch, mode = get_keystone_arch(arch=arch_s, mode=mode_s, endian=is_big_endian())
            else:
                # if not alive, defaults to x86-32
                arch_s = "X86"
                mode_s = "32"
                endian_s = "little"
                arch, mode = get_keystone_arch(arch=arch_s, mode=mode_s, endian=False)
        elif not arch_s:
            err("An architecture (-a) must be provided")
            return
        elif not mode_s:
            err("A mode (-m) must be provided")
            return
        else:
            arch, mode = get_keystone_arch(arch=arch_s, mode=mode_s, endian=big_endian)
            endian_s = "big" if big_endian else "little"

        insns = " ".join(args)
        insns = [x.strip() for x in insns.split(";") if x is not None]

        info("Assembling {} instruction{} for {} ({} endian)".format(len(insns),
                                                                     "s" if len(insns)>1 else "",
                                                                     ":".join([arch_s, mode_s]),
                                                                     endian_s))

        if as_shellcode:
            gef_print("""sc="" """)

        raw = b""
        for insn in insns:
            res = keystone_assemble(insn, arch, mode, raw=True)
            if res is None:
                gef_print("(Invalid)")
                continue

            if write_to_location:
                raw += res
                continue

            s = binascii.hexlify(res)
            res = b"\\x" + b"\\x".join([s[i:i + 2] for i in range(0, len(s), 2)])
            res = res.decode("utf-8")

            if as_shellcode:
                res = """sc+="{0:s}" """.format(res)

            gef_print("{0:60s} # {1}".format(res, insn))

        if write_to_location:
            l = len(raw)
            info("Overwriting {:d} bytes at {:s}".format(l, format_address(write_to_location)))
            write_memory(write_to_location, raw, l)
        return


@register_command
class ProcessListingCommand(GenericCommand):
    """List and filter process. If a PATTERN is given as argument, results shown will be grepped
    by this pattern."""

    _cmdline_ = "process-search"
    _syntax_  = "{:s} [PATTERN]".format(_cmdline_)
    _aliases_ = ["ps",]
    _example_ = "{:s} gdb".format(_cmdline_)

    def __init__(self):
        super(ProcessListingCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("ps_command", "/bin/ps auxww", "`ps` command to get process information")
        return

    def do_invoke(self, argv):
        do_attach = False
        smart_scan = False

        opts, args = getopt.getopt(argv, "as")
        for o, _ in opts:
            if o == "-a": do_attach  = True
            if o == "-s": smart_scan = True

        pattern = re.compile("^.*$") if not args else re.compile(args[0])

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
                ok("Attaching to process='{:s}' pid={:d}".format(process["command"], pid))
                gdb.execute("attach {:d}".format(pid))
                return None

            line = [process[i] for i in ("pid", "user", "cpu", "mem", "tty", "command")]
            gef_print("\t\t".join(line))

        return None


    def get_processes(self):
        output = gef_execute_external(self.get_setting("ps_command").split(), True)
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


@register_command
class ElfInfoCommand(GenericCommand):
    """Display a limited subset of ELF header information. If no argument is provided, the command will
    show information about the current ELF being debugged."""

    _cmdline_ = "elf-info"
    _syntax_  = "{:s} [FILE]".format(_cmdline_)
    _example_  = "{:s} /bin/ls".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(ElfInfoCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return


    def do_invoke(self, argv):
        # http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        classes = {0x01: "32-bit",
                   0x02: "64-bit",}
        endianness = {0x01: "Little-Endian",
                      0x02: "Big-Endian",}
        osabi = {
            0x00: "System V",
            0x01: "HP-UX",
            0x02: "NetBSD",
            0x03: "Linux",
            0x06: "Solaris",
            0x07: "AIX",
            0x08: "IRIX",
            0x09: "FreeBSD",
            0x0C: "OpenBSD",
        }

        types = {
            0x01: "Relocatable",
            0x02: "Executable",
            0x03: "Shared",
            0x04: "Core"
        }

        machines = {
            0x02: "SPARC",
            0x03: "x86",
            0x08: "MIPS",
            0x12: "SPARC64",
            0x14: "PowerPC",
            0x15: "PowerPC64",
            0x28: "ARM",
            0x32: "IA-64",
            0x3E: "x86-64",
            0xB7: "AArch64",
        }

        filename = argv[0] if argv else get_filepath()
        if filename is None:
            return

        elf = get_elf_headers(filename)
        if elf is None:
            return

        data = [
            ("Magic", "{0!s}".format(hexdump(struct.pack(">I",elf.e_magic), show_raw=True))),
            ("Class", "{0:#x} - {1}".format(elf.e_class, classes[elf.e_class])),
            ("Endianness", "{0:#x} - {1}".format(elf.e_endianness, endianness[elf.e_endianness])),
            ("Version", "{:#x}".format(elf.e_eiversion)),
            ("OS ABI", "{0:#x} - {1}".format(elf.e_osabi, osabi[elf.e_osabi])),
            ("ABI Version", "{:#x}".format(elf.e_abiversion)),
            ("Type", "{0:#x} - {1}".format(elf.e_type, types[elf.e_type])),
            ("Machine", "{0:#x} - {1}".format(elf.e_machine, machines[elf.e_machine])),
            ("Program Header Table" , "{}".format(format_address(elf.e_phoff))),
            ("Section Header Table" , "{}".format(format_address(elf.e_shoff))),
            ("Header Table" , "{}".format(format_address(elf.e_phoff))),
            ("ELF Version", "{:#x}".format(elf.e_version)),
            ("Header size" , "{0} ({0:#x})".format(elf.e_ehsize)),
            ("Entry point", "{}".format(format_address(elf.e_entry))),
        ]

        for title, content in data:
            gef_print("{:<30}: {}".format(Color.boldify(title), content))
        return


@register_command
class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it. The command will test for
    well-known symbols for entry points, such as `main`, `_main`, `__libc_start_main`, etc. defined by
    the setting `entrypoint_symbols`."""

    _cmdline_ = "entry-break"
    _syntax_  = _cmdline_
    _aliases_ = ["start",]

    def __init__(self, *args, **kwargs):
        super(EntryPointBreakCommand, self).__init__()
        self.add_setting("entrypoint_symbols", "main _main __libc_start_main __uClibc_main start _start", "Possible symbols for entry points")
        return

    def do_invoke(self, argv):
        fpath = get_filepath()
        if fpath is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn("The file '{}' is not executable.".format(fpath))
            return

        if is_alive():
            warn("gdb is already running")
            return

        bp = None
        entrypoints = self.get_setting("entrypoint_symbols").split()

        for sym in entrypoints:
            try:
                value = gdb.parse_and_eval(sym)
                info("Breaking at '{:s}'".format(str(value)))
                bp = EntryBreakBreakpoint(sym)
                gdb.execute("run {}".format(" ".join(argv)))
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
        elf = get_elf_headers()
        if elf is None:
            return

        if self.is_pie(fpath):
            self.set_init_tbreak_pie(elf.e_entry)
            gdb.execute("continue")
            return

        self.set_init_tbreak(elf.e_entry)
        gdb.execute("run")
        return

    def set_init_tbreak(self, addr):
        info("Breaking at entry-point: {:#x}".format(addr))
        bp = EntryBreakBreakpoint("*{:#x}".format(addr))
        return bp

    def set_init_tbreak_pie(self, addr):
        warn("PIC binary detected, retrieving text base address")
        gdb.execute("set stop-on-solib-events 1")
        disable_context()
        gdb.execute("run")
        enable_context()
        gdb.execute("set stop-on-solib-events 0")
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        return self.set_init_tbreak(base_address + addr)

    def is_pie(self, fpath):
        return checksec(fpath)["PIE"]


@register_command
class ContextCommand(GenericCommand):
    """Displays a comprehensive and modular summary of runtime context. Unless setting `enable` is
    set to False, this command will be spawned automatically every time GDB hits a breakpoint, a
    watchpoint, or any kind of interrupt. By default, it will show panes that contain the register
    states, the stack, and the disassembly code around $pc."""

    _cmdline_ = "context"
    _syntax_  = _cmdline_
    _aliases_ = ["ctx",]

    old_registers = {}

    def __init__(self):
        super(ContextCommand, self).__init__()
        self.add_setting("enable", True, "Enable/disable printing the context when breaking")
        self.add_setting("show_stack_raw", False, "Show the stack pane as raw hexdump (no dereference)")
        self.add_setting("show_registers_raw", False, "Show the registers pane with raw values (no dereference)")
        self.add_setting("peek_calls", True, "Peek into calls")
        self.add_setting("peek_ret", True, "Peek at return address")
        self.add_setting("nb_lines_stack", 8, "Number of line in the stack pane")
        self.add_setting("grow_stack_down", False, "Order of stack downward starts at largest down to stack pointer")
        self.add_setting("nb_lines_backtrace", 10, "Number of line in the backtrace pane")
        self.add_setting("nb_lines_threads", -1, "Number of line in the threads pane")
        self.add_setting("nb_lines_code", 6, "Number of instruction after $pc")
        self.add_setting("nb_lines_code_prev", 3, "Number of instruction before $pc")
        self.add_setting("ignore_registers", "", "Space-separated list of registers not to display (e.g. '$cs $ds $gs')")
        self.add_setting("clear_screen", False, "Clear the screen before printing the context")
        self.add_setting("layout", "legend regs stack code args source memory threads trace extra", "Change the order/presence of the context sections")
        self.add_setting("redirect", "", "Redirect the context information to another TTY")

        if "capstone" in list(sys.modules.keys()):
            self.add_setting("use_capstone", False, "Use capstone as disassembler in the code pane (instead of GDB)")

        self.layout_mapping = {
            "legend":  self.show_legend,
            "regs":  self.context_regs,
            "stack": self.context_stack,
            "code": self.context_code,
            "args": self.context_args,
            "memory": self.context_memory,
            "source": self.context_source,
            "trace": self.context_trace,
            "threads": self.context_threads,
            "extra": self.context_additional_information,
        }
        return

    def post_load(self):
        gef_on_continue_hook(self.update_registers)
        gef_on_continue_hook(self.empty_extra_messages)
        return

    def show_legend(self):
        if get_gef_setting("gef.disable_color")!=True:
            str_color = get_gef_setting("theme.dereference_string")
            code_addr_color = get_gef_setting("theme.address_code")
            stack_addr_color = get_gef_setting("theme.address_stack")
            heap_addr_color = get_gef_setting("theme.address_heap")
            changed_register_color = get_gef_setting("theme.registers_value_changed")

            gef_print("[ Legend: {} | {} | {} | {} | {} ]".format(Color.colorify("Modified register", attrs=changed_register_color),
                                                                  Color.colorify("Code", attrs=code_addr_color),
                                                                  Color.colorify("Heap", attrs=heap_addr_color),
                                                                  Color.colorify("Stack", attrs=stack_addr_color),
                                                                  Color.colorify("String", attrs=str_color)))
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if not self.get_setting("enable"):
            return

        current_layout = self.get_setting("layout").strip().split()
        if not current_layout:
            return

        self.tty_rows, self.tty_columns = get_terminal_size()

        redirect = self.get_setting("redirect")
        if redirect and os.access(redirect, os.W_OK):
            enable_redirect_output(to_file=redirect)

        if self.get_setting("clear_screen"):
            clear_screen(redirect)

        for section in current_layout:
            if section[0] == "-":
                continue

            try:
                self.layout_mapping[section]()
            except gdb.MemoryError as e:
                # a MemoryError will happen when $pc is corrupted (invalid address)
                err(str(e))


        self.context_title("")

        if redirect and os.access(redirect, os.W_OK):
            disable_redirect_output()
        return

    def context_title(self, m):
        line_color= get_gef_setting("theme.context_title_line")
        msg_color = get_gef_setting("theme.context_title_message")

        if not m:
            gef_print(Color.colorify(HORIZONTAL_LINE * self.tty_columns, line_color))
            return

        trail_len = len(m) + 8
        title = ""
        title += Color.colorify("{:{padd}<{width}}[ ".format("",
                                                             width=self.tty_columns - trail_len,
                                                             padd=HORIZONTAL_LINE),
                                attrs=line_color)
        title += Color.colorify(m, msg_color)
        title += Color.colorify(" ]{:{padd}<4}".format("", padd=HORIZONTAL_LINE),
                                attrs=line_color)
        gef_print(title)
        return

    def context_regs(self):
        self.context_title("registers")
        ignored_registers = set(self.get_setting("ignore_registers").split())

        if self.get_setting("show_registers_raw") == False:
            regs = set([x.strip() for x in current_arch.all_registers])
            printable_registers = " ".join(list(regs - ignored_registers))
            gdb.execute("registers {}".format(printable_registers))
            return

        l = max(map(len, current_arch.all_registers))
        l += 5
        l += 16 if is_elf64() else 8
        nb = get_terminal_size()[1]//l
        i = 1
        line = ""
        color = get_gef_setting("theme.registers_value_changed")

        for reg in current_arch.all_registers:
            if reg.strip() in ignored_registers:
                continue

            try:
                r = gdb.parse_and_eval(reg)
                if r.type.code == gdb.TYPE_CODE_VOID:
                    continue

                new_value_type_flag = (r.type.code == gdb.TYPE_CODE_FLAGS)
                new_value = long(r)

            except (gdb.MemoryError, gdb.error):
                # If this exception is triggered, it means that the current register
                # is corrupted. Just use the register "raw" value (not eval-ed)
                new_value = get_register(reg)
                new_value_type_flag = False

            except Exception:
                new_value = 0

            old_value = self.old_registers.get(reg, 0)

            line += "{:s}  ".format(Color.greenify(reg))
            if new_value_type_flag:
                line += "{:s} ".format(str(new_value))
            else:
                new_value = align_address(new_value)
                old_value = align_address(old_value)
                if new_value == old_value:
                    line += "{:s} ".format(format_address_spaces(new_value))
                else:
                    line += "{:s} ".format(Color.colorify(format_address_spaces(new_value), attrs=color))

            if i % nb == 0 :
                gef_print(line)
                line = ""
            i += 1

        if line:
            gef_print(line)

        gef_print("Flags: {:s}".format(current_arch.flag_register_to_human()))
        return

    def context_stack(self):
        self.context_title("stack")

        show_raw = self.get_setting("show_stack_raw")
        nb_lines = self.get_setting("nb_lines_stack")

        try:
            sp = current_arch.sp
            if show_raw == True:
                mem = read_memory(sp, 0x10 * nb_lines)
                gef_print(hexdump(mem, base=sp))
            else:
                gdb.execute("dereference {:#x} l{:d}".format(sp, nb_lines))

        except gdb.MemoryError:
            err("Cannot read memory from $SP (corrupted stack pointer?)")

        return

    def context_code(self):
        nb_insn = self.get_setting("nb_lines_code")
        nb_insn_prev = self.get_setting("nb_lines_code_prev")
        use_capstone = self.has_setting("use_capstone") and self.get_setting("use_capstone")
        cur_insn_color = get_gef_setting("theme.disassemble_current_instruction")
        pc = current_arch.pc

        frame = gdb.selected_frame()
        arch = frame.architecture()
        arch_name = arch.name().lower()
        if is_arm_thumb():
            arch_name += ":thumb"
            pc   += 1

        self.context_title("code:{}".format(arch_name))

        try:
            instruction_iterator = capstone_disassemble if use_capstone else gef_disassemble

            for insn in instruction_iterator(pc, nb_insn, nb_prev=nb_insn_prev):
                line = []
                is_taken  = False
                target    = None
                text = str(insn)

                if insn.address < pc:
                    line += Color.grayify("   {}".format(text))

                elif insn.address == pc:
                    line += Color.colorify("{:s}{:s}".format(RIGHT_ARROW, text), attrs=cur_insn_color)

                    if current_arch.is_conditional_branch(insn):
                        is_taken, reason = current_arch.is_branch_taken(insn)
                        if is_taken:
                            target = insn.operands[-1].split()[0]
                            reason = "[Reason: {:s}]".format(reason) if reason else ""
                            line += Color.colorify("\tTAKEN {:s}".format(reason), attrs="bold green")
                        else:
                            reason = "[Reason: !({:s})]".format(reason) if reason else ""
                            line += Color.colorify("\tNOT taken {:s}".format(reason), attrs="bold red")
                    elif current_arch.is_call(insn) and self.get_setting("peek_calls") == True:
                        target = insn.operands[-1].split()[0]
                    elif current_arch.is_ret(insn) and self.get_setting("peek_ret") == True:
                        target = current_arch.get_ra(insn, frame)

                else:
                    line += "   {}".format(text)

                gef_print("".join(line))

                if target:
                    try:
                        target = int(target, 0)
                    except TypeError:  # Already an int
                        pass
                    except ValueError:
                        # If the operand isn't an address right now we can't parse it
                        continue
                    for i, tinsn in enumerate(instruction_iterator(target, nb_insn)):
                        text= "   {}  {}".format (DOWN_ARROW if i==0 else " ", str(tinsn))
                        gef_print(text)
                    break

        except gdb.MemoryError:
            err("Cannot disassemble from $PC")
        return

    def context_args(self):
        insn = gef_current_instruction(current_arch.pc)
        if not current_arch.is_call(insn):
            return

        self.size2type = {
            1: "BYTE",
            2: "WORD",
            4: "DWORD",
            8: "QWORD",
        }

        if insn.operands[-1].startswith(self.size2type[current_arch.ptrsize]+" PTR"):
            target = "*" + insn.operands[-1].split()[-1]
        elif '$'+insn.operands[0] in current_arch.all_registers_stripped:
            target = "*{:#x}".format(get_register('$'+insn.operands[0]))
        else:
            # is there a symbol?
            ops = " ".join(insn.operands)
            if "<" in ops and ">" in ops:
                # extract it
                target = re.sub(r".*<([^\(>]*).*", r"\1", ops)
            else:
                # it's an address, just use as is
                target = re.sub(r".*(0x[a-fA-F0-9]*).*", r"\1", ops)

        sym = gdb.lookup_global_symbol(target)
        if sym is None:
            self.print_guessed_arguments(target)
            return

        if sym.type.code != gdb.TYPE_CODE_FUNC:
            err("Symbol '{}' is not a function: type={}".format(target, sym.type.code))
            return

        self.print_arguments_from_symbol(target, sym)
        return

    def get_ith_parameter(self, i):
        """Retrieves the correct parameter used for the current function call."""
        if is_x86_32():
            sp = current_arch.sp
            sz =  current_arch.ptrsize
            loc = sp + (i * sz) + sz
            val = read_int_from_memory(loc)
            key = "[sp + {:#x}]".format(i * sz)
        else:
            reg = current_arch.function_parameters[i]
            val = get_register(reg)
            key = reg
        return (key, val)

    def print_arguments_from_symbol(self, function_name, symbol):
        """If symbols were found, parse them and print the argument adequately."""
        args = []

        for i, f in enumerate(symbol.type.fields()):
            _value = self.get_ith_parameter(i)[1]
            _value = RIGHT_ARROW.join(DereferenceCommand.dereference_from(_value))
            _name = f.name or "var_{}".format(i)
            _type = f.type.name or self.size2type[f.type.sizeof]
            args.append("{} {} = {}".format(_type, _name, _value))

        self.context_title("arguments")

        if not args:
            gef_print("{} (<void>)".format(function_name))
            return

        gef_print("{} (".format(function_name))
        gef_print("   " + ",\n   ".join(args))
        gef_print(")")
        return

    def print_guessed_arguments(self, function_name):
        """When no symbol, read the current basic block and look for "interesting" instructions."""

        def __get_current_block_start_address():
            pc = current_arch.pc
            try:
                block_start = gdb.block_for_pc(pc).start
            except RuntimeError:
                # if stripped, let's roll back 5 instructions
                block_start = gdb_get_nth_previous_instruction_address(pc, 5)
            return block_start


        parameter_set = set()
        pc = current_arch.pc
        block_start = __get_current_block_start_address()
        use_capstone = self.has_setting("use_capstone") and self.get_setting("use_capstone")
        instruction_iterator = capstone_disassemble if use_capstone else gef_disassemble
        function_parameters = current_arch.function_parameters

        for insn in instruction_iterator(block_start, pc-block_start):
            if len(insn.operands) < 1:
                continue

            if is_x86_32():
                if insn.mnemonic == "push":
                    parameter_set.add(insn.operands[0])
            else:
                op = "$"+insn.operands[0]
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
            nb_argument = 0
            for p in parameter_set:
                nb_argument = max(nb_argument, function_parameters.index(p)+1)

        args = []
        for i in range(nb_argument):
            _key, _value = self.get_ith_parameter(i)
            _value = RIGHT_ARROW.join(DereferenceCommand.dereference_from(_value))
            args.append("{} = {}".format(_key, _value))

        self.context_title("arguments (guessed)")
        gef_print("{} (".format(function_name))
        if args:
            gef_print("   "+",\n   ".join(args))
        gef_print(")")
        return


    def context_source(self):
        try:
            pc = current_arch.pc
            symtabline = gdb.find_pc_line(pc)
            symtab = symtabline.symtab
            line_num = symtabline.line - 1     # we substract one because line number returned by gdb start at 1
            if not symtab.is_valid():
                return

            fpath = symtab.fullname()
            with open(fpath, "r") as f:
                lines = [l.rstrip() for l in f.readlines()]

        except Exception:
            return

        nb_line = self.get_setting("nb_lines_code")
        title = "source:{0:s}+{1:d}".format(symtab.filename, line_num + 1)
        cur_line_color = get_gef_setting("theme.source_current_line")
        self.context_title(title)

        for i in range(line_num - nb_line + 1, line_num + nb_line):
            if i < 0:
                continue

            if i < line_num:
                gef_print(Color.grayify("   {:4d}\t {:s}".format(i + 1, lines[i],)))

            if i == line_num:
                extra_info = self.get_pc_context_info(pc, lines[i])
                if extra_info:
                    gef_print(extra_info)
                gef_print(Color.colorify("{}{:4d}\t {:s}".format(RIGHT_ARROW, i + 1, lines[i]), attrs=cur_line_color))

            if i > line_num:
                try:
                    gef_print("   {:4d}\t {:s}".format(i + 1, lines[i],))
                except IndexError:
                    break
        return

    def get_pc_context_info(self, pc, line):
        try:
            current_block = gdb.block_for_pc(pc)
            if not current_block.is_valid(): return ""
            m = collections.OrderedDict()
            while current_block and not current_block.is_static:
                for sym in current_block:
                    symbol = sym.name
                    if not sym.is_function and re.search(r"\W{}\W".format(symbol), line):
                        val = gdb.parse_and_eval(symbol)
                        if val.type.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                            addr = long(val.address)
                            addrs = DereferenceCommand.dereference_from(addr)
                            if len(addrs) > 2:
                                addrs = [addrs[0], "[...]", addrs[-1]]

                            f = " {:s} ".format(RIGHT_ARROW)
                            val = f.join(addrs)
                        elif val.type.code == gdb.TYPE_CODE_INT:
                            val = hex(long(val))
                        else:
                            continue

                        if symbol not in m:
                            m[symbol] = val
                current_block = current_block.superblock

            if m:
                return "\t\t// " + ", ".join(["{:s}={:s}".format(Color.yellowify(a),b) for a, b in m.items()])
        except Exception:
            pass
        return ""

    def context_trace(self):
        self.context_title("trace")

        nb_backtrace = self.get_setting("nb_lines_backtrace")
        if nb_backtrace <= 0:
            return
        orig_frame = current_frame = gdb.selected_frame()
        i = 0

        # backward compat for gdb (gdb < 7.10)
        if not hasattr(gdb, "FrameDecorator"):
            gdb.execute("backtrace {:d}".format(nb_backtrace))
            return

        while current_frame:
            current_frame.select()
            if not current_frame.is_valid():
                continue

            pc = current_frame.pc()
            name = current_frame.name()
            items = []
            items.append("{:#x}".format(pc))
            if name:
                frame_args = gdb.FrameDecorator.FrameDecorator(current_frame).frame_args() or []
                m = "Name: {:s}({:s})".format(Color.greenify(name),
                                              ", ".join(["{!s}={!s}".format(x.sym, x.sym.value(current_frame)) for x in frame_args]))
                items.append(m)
            else:
                try:
                    insn = next(gef_disassemble(pc, 1))
                except gdb.MemoryError:
                    break
                items.append(Color.redify("{} {}".format(insn.mnemonic, ', '.join(insn.operands))))

            gef_print("[{:s}] {:s}".format(Color.colorify("#{:d}".format(i), "bold pink"),
                                       RIGHT_ARROW.join(items)))
            current_frame = current_frame.older()
            i += 1
            nb_backtrace -= 1
            if nb_backtrace == 0:
                break

        orig_frame.select()
        return

    def context_threads(self):
        def reason():
            res = gdb.execute("info program", to_string=True).splitlines()
            if not res:
                return "NOT RUNNING"

            for line in res:
                line = line.strip()
                if line.startswith("It stopped with signal "):
                    return line.replace("It stopped with signal ", "").split(",", 1)[0]
                if  line == "The program being debugged is not being run.":
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
        idx = self.get_setting("nb_lines_threads")
        if idx > 0:
            threads = threads[0:idx]

        if idx==0:
            return

        if len(threads) < 1:
            err("No thread selected")
            return

        for i, thread in enumerate(threads):
            line = """[{:s}] Id {:d}, Name: "{:s}", """.format(Color.colorify("#{:d}".format(i), attrs="bold pink"),
                                                               thread.num, thread.name or "")
            if thread.is_running():
                line += Color.colorify("running", attrs="bold green")
            elif thread.is_stopped():
                line += Color.colorify("stopped", attrs="bold red")
                line += ", reason: {}".format(Color.colorify(reason(), attrs="bold pink"))
            elif thread.is_exited():
                line += Color.colorify("exited", attrs="bold yellow")

            gef_print(line)
            i += 1
        return


    def context_additional_information(self):
        if not __context_messages__:
            return

        self.context_title("extra")
        for level, text in __context_messages__:
            if   level=="error": err(text)
            elif level=="warn": warn(text)
            elif level=="success": ok(text)
            else: info(text)
        return

    def context_memory(self):
        global __watches__
        for address, opt in sorted(__watches__.items()):
            self.context_title("memory:{:#x}".format(address))
            gdb.execute('hexdump {fmt:s} {address:d} {size:d}'.format(
                address=address,
                size=opt[0],
                fmt=opt[1]
            ))

    @classmethod
    def update_registers(cls, event):
        for reg in current_arch.all_registers:
            try:
                cls.old_registers[reg] = get_register(reg)
            except Exception:
                cls.old_registers[reg] = 0
        return


    def empty_extra_messages(self, event):
        global __context_messages__
        __context_messages__ = []
        return


@register_command
class MemoryCommand(GenericCommand):
    """Add or remove address ranges to the memory view."""
    _cmdline_ = "memory"
    _syntax_  = "{:s}".format(_cmdline_)

    def __init__(self):
        super(MemoryCommand, self).__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.usage()
        return

@register_command
class MemoryWatchCommand(GenericCommand):
    """Adds address ranges to the memory view."""
    _cmdline_ = "memory watch"
    _syntax_  = "{:s} ADDRESS [SIZE] [(qword|dword|word|byte)]".format(_cmdline_)
    _example_ = "\n\t{0:s} 0x603000 0x100 byte\n\t{0:s} $sp".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __watches__

        if len(argv) not in (1, 2, 3):
            self.usage()
            return

        address = to_unsigned_long(gdb.parse_and_eval(argv[0]))
        size    = to_unsigned_long(gdb.parse_and_eval(argv[1])) if len(argv) > 1  else 0x10
        group   = "byte"

        if len(argv) == 3:
            group = argv[2].lower()
            if group not in ("qword", "dword", "word", "byte"):
                warn("Unexpected grouping '{}'".format(group))
                self.usage()
                return
        else:
            if current_arch.ptrsize == 4:
                group = "dword"
            elif current_arch.ptrsize == 8:
                group = "qword"

        __watches__[address] = (size, group)
        ok("Adding memwatch to {:#x}".format(address))
        return

@register_command
class MemoryUnwatchCommand(GenericCommand):
    """Removes address ranges to the memory view."""
    _cmdline_ = "memory unwatch"
    _syntax_  = "{:s} ADDRESS".format(_cmdline_)
    _example_ = "\n\t{0:s} 0x603000\n\t{0:s} $sp".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __watches__
        if len(argv) < 1:
            self.usage()
            return

        address = to_unsigned_long(gdb.parse_and_eval(argv[0]))
        res = __watches__.pop(address, None)
        if not res:
            warn("You weren't watching {:#x}".format(address))
        else:
            ok("Removed memwatch of {:#x}".format(address))
        return

@register_command
class MemoryWatchResetCommand(GenericCommand):
    """Removes all watchpoints."""
    _cmdline_ = "memory reset"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __watches__
        __watches__.clear()
        ok("Memory watches cleared")
        return

@register_command
class MemoryWatchListCommand(GenericCommand):
    """Lists all watchpoints to display in context layout."""
    _cmdline_ = "memory list"
    _syntax_  = "{:s}".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __watches__

        if not __watches__:
            info("No memory watches")
            return

        info("Memory watches:")
        for address, opt in sorted(__watches__.items()):
            gef_print("- {:#x} ({}, {})".format(address, opt[0], opt[1]))
        return


@register_command
class HexdumpCommand(GenericCommand):
    """Display SIZE lines of hexdump from the memory location pointed by ADDRESS. """

    _cmdline_ = "hexdump"
    _syntax_  = "{:s} (qword|dword|word|byte) ADDRESS [[L][SIZE]] [UP|DOWN] [S]".format(_cmdline_)
    _example_ = "{:s} byte $rsp L16 DOWN".format(_cmdline_)

    def __init__(self):
        super(HexdumpCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 2:
            self.usage()
            return

        fmt, argv = argv[0], argv[1:]
        if fmt not in {"qword", "dword", "word", "byte"}:
            self.usage()
            return

        start_addr = to_unsigned_long(gdb.parse_and_eval(argv[0]))
        read_from = align_address(start_addr)
        read_len = 0x40 if fmt=="byte" else 0x10
        up_to_down = True

        if argc >= 2:
            for arg in argv[1:]:
                arg = arg.lower()
                if arg.startswith("l"):
                    arg = arg[1:]
                try:
                    read_len = long(arg, 0)
                    continue
                except ValueError:
                    pass

                if arg == "up":
                    up_to_down = True
                    continue
                elif arg == "down":
                    up_to_down = False
                    continue

        if fmt == "byte":
            mem = read_memory(read_from, read_len)
            lines = hexdump(mem, base=read_from).splitlines()
        else:
            lines = self._hexdump(read_from, read_len, fmt)

        if not up_to_down:
            lines.reverse()

        gef_print("\n".join(lines))
        return


    def _hexdump(self, start_addr, length, arrange_as):
        elf = get_elf_headers()
        if elf is None:
            return
        endianness = endian_str()

        formats = {
            "qword": ("Q", 8),
            "dword": ("I", 4),
            "word": ("H", 2),
        }

        r, l = formats[arrange_as]
        fmt_str = "%#x+%.4x %s  {:s} %#.{:s}x".format(VERTICAL_LINE, str(l * 2))
        fmt_pack = endianness + r
        lines = []

        i = 0
        while i < length:
            cur_addr = start_addr + i * l
            sym = gdb_get_location_from_symbol(cur_addr)
            sym = "<{:s}+{:04x}>".format(*sym) if sym else ''
            mem = read_memory(cur_addr, l)
            val = struct.unpack(fmt_pack, mem)[0]
            lines.append(fmt_str % (cur_addr, i * l,  sym, val))
            i += 1

        return lines


@register_command
class PatchCommand(GenericCommand):
    """Write specified values to the specified address."""

    _cmdline_ = "patch"
    _syntax_  = ("{0:s} <qword|dword|word|byte> <location> <values>\n"
                 "{0:s} string <location> \"double-escaped string\"".format(_cmdline_))
    SUPPORTED_SIZES = {
        "qword": (8, "Q"),
        "dword": (4, "L"),
        "word": (2, "H"),
        "byte": (1, "B"),
    }

    def __init__(self):
        super(PatchCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 3:
            self.usage()
            return

        fmt, location, values = argv[0].lower(), argv[1], argv[2:]
        if fmt not in self.SUPPORTED_SIZES:
            self.usage()
            return

        addr = align_address(long(gdb.parse_and_eval(location)))
        size, fcode = self.SUPPORTED_SIZES[fmt]

        d = "<" if is_little_endian() else ">"
        for value in values:
            value = int(value, 0) & ((1 << size * 8) - 1)
            vstr = struct.pack(d + fcode, value)
            write_memory(addr, vstr, length=size)
            addr += size

        return

@register_command
class PatchStringCommand(GenericCommand):
    """Write specified string to the specified memory location pointed by ADDRESS."""

    _cmdline_ = "patch string"
    _syntax_  = "{:s} ADDRESS \"double backslash-escaped string\"".format(_cmdline_)
    _example_ = "{:s} $sp \"GEFROCKS\"".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc != 2:
            self.usage()
            return

        location, s = argv[0:2]
        addr = align_address(long(gdb.parse_and_eval(location)))

        try:
            s = codecs.escape_decode(s)[0]
        except binascii.Error:
            gef_print("Could not decode '\\xXX' encoded string \"{}\"".format(s))
            return

        write_memory(addr, s, len(s))
        return


@register_command
class DereferenceCommand(GenericCommand):
    """Dereference recursively from an address and display information. This acts like WinDBG `dps`
    command."""

    _cmdline_ = "dereference"
    _syntax_  = "{:s} [LOCATION] [l[NB]]".format(_cmdline_)
    _aliases_ = ["telescope", ]
    _example_ = "{:s} $sp l20".format(_cmdline_)

    def __init__(self):
        super(DereferenceCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_recursion", 7, "Maximum level of pointer recursion")
        return

    @staticmethod
    def pprint_dereferenced(addr, off):
        base_address_color = get_gef_setting("theme.dereference_base_address")
        registers_color = get_gef_setting("theme.dereference_register_value")

        regs = [(k.strip(), get_register(k)) for k in current_arch.all_registers]

        sep = " {:s} ".format(RIGHT_ARROW)
        memalign = current_arch.ptrsize

        offset = off * memalign
        current_address = align_address(addr + offset)
        addrs = DereferenceCommand.dereference_from(current_address)
        l  = ""
        addr_l = format_address(long(addrs[0], 16))
        l += "{:s}{:s}+{:#04x}: {:{ma}s}".format(Color.colorify(addr_l, attrs=base_address_color),
                                                 VERTICAL_LINE, offset,
                                                 sep.join(addrs[1:]), ma=(memalign*2 + 2))

        register_hints = []

        for regname, regvalue in regs:
            if current_address == regvalue:
                register_hints.append(regname)

        if register_hints:
            m = "\t{:s}{:s}".format(LEFT_ARROW, ", ".join(list(register_hints)))
            l += Color.colorify(m, attrs=registers_color)

        offset += memalign
        return l


    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)

        if argc < 1:
            err("Missing location.")
            return

        nb = 10
        if argc==2 and argv[1][0] in ("l", "L") and argv[1][1:].isdigit():
            nb = int(argv[1][1:])
        elif argc == 2 and argv[1].isdigit():
            nb = int(argv[1])

        addr = safe_parse_and_eval(argv[0])
        if addr is None:
            err("Invalid address")
            return

        addr = long(addr)
        if process_lookup_address(addr) is None:
            err("Unmapped address")
            return

        if get_gef_setting("context.grow_stack_down") == True:
            from_insnum = nb-1
            to_insnum = -1
            insnum_step = -1
        else:
            from_insnum = 0
            to_insnum = nb
            insnum_step = 1

        start_address = align_address(addr)

        for i in range(from_insnum, to_insnum, insnum_step):
            gef_print(DereferenceCommand.pprint_dereferenced(start_address, i))

        return


    @staticmethod
    def dereference_from(addr):
        if not is_alive():
            return [format_address(addr),]

        code_color = get_gef_setting("theme.dereference_code")
        string_color = get_gef_setting("theme.dereference_string")
        max_recursion = get_gef_setting("dereference.max_recursion") or 10
        addr = lookup_address(align_address(long(addr)))
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
                if addr.section.is_executable() and addr.is_in_text_segment() and not is_readable_string(addr.value):
                    insn = gef_current_instruction(addr.value)
                    insn_str = "{} {} {}".format(insn.location, insn.mnemonic, ", ".join(insn.operands))
                    msg.append(Color.colorify(insn_str, attrs=code_color))
                    break

                elif addr.section.permission.value & Permission.READ:
                    if is_readable_string(addr.value):
                        s = read_cstring_from_memory(addr.value)
                        if len(s) < get_memory_alignment():
                            txt = '{:s} ("{:s}"?)'.format(format_address(deref), Color.colorify(s, attrs=string_color))
                        elif len(s) >= 50:
                            txt = Color.colorify('"{:s}[...]"'.format(s[:50]), attrs=string_color)
                        else:
                            txt = Color.colorify('"{:s}"'.format(s), attrs=string_color)

                        msg.append(txt)
                        break

            # if not able to parse cleanly, simply display and break
            val = "{:#0{ma}x}".format(long(deref & 0xFFFFFFFFFFFFFFFF), ma=(current_arch.ptrsize * 2 + 2))
            msg.append(val)
            break

        return msg


@register_command
class ASLRCommand(GenericCommand):
    """View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not
    attached). This command allows to change that setting."""

    _cmdline_ = "aslr"
    _syntax_  = "{:s} (on|off)".format(_cmdline_)

    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            ret = gdb.execute("show disable-randomization", to_string=True)
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


@register_command
class ResetCacheCommand(GenericCommand):
    """Reset cache of all stored data. This command is here for debugging and test purposes, GEF
    handles properly the cache reset under "normal" scenario."""

    _cmdline_ = "reset-cache"
    _syntax_  = _cmdline_

    def do_invoke(self, argv):
        reset_all_caches()
        return


@register_command
class VMMapCommand(GenericCommand):
    """Display a comprehensive layout of the virtual memory mapping. If a filter argument, GEF will
    filter out the mapping whose pathname do not match that filter."""

    _cmdline_ = "vmmap"
    _syntax_  = "{:s} [FILTER]".format(_cmdline_)
    _example_ = "{:s} libc".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        vmmap = get_process_maps()
        if not vmmap:
            err("No address mapping information found")
            return

        color = get_gef_setting("theme.xinfo_title_message")
        headers = [Color.colorify(x, attrs=color) for x in ["Start", "End", "Offset", "Perm", "Path"]]
        if is_elf64():
            gef_print("{:<31s} {:<31s} {:<31s} {:<4s} {:s}".format(*headers))
        else:
            gef_print("{:<23s} {:<23s} {:<23s} {:<4s} {:s}".format(*headers))

        for entry in vmmap:
            if argv and not argv[0] in entry.path:
                continue
            l = []
            l.append(format_address(entry.page_start))
            l.append(format_address(entry.page_end))
            l.append(format_address(entry.offset))

            if entry.permission.value == (Permission.READ|Permission.WRITE|Permission.EXECUTE) :
                l.append(Color.colorify(str(entry.permission), attrs="bold red"))
            else:
                l.append(str(entry.permission))

            l.append(entry.path)
            gef_print(" ".join(l))
        return


@register_command
class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary. This command extends the GDB command
    `info files`, by retrieving more information from extra sources, and providing a better
    display. If an argument FILE is given, the output will grep information related to only that file.
    If an argument name is also given, the output will grep to the name within FILE."""

    _cmdline_ = "xfiles"
    _syntax_  = "{:s} [FILE [NAME]]".format(_cmdline_)
    _example_ = "\n{0:s} libc\n{0:s} libc IO_vtables".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        color = get_gef_setting("theme.xinfo_title_message")
        headers = [Color.colorify(x, attrs=color) for x in ["Start", "End", "Name", "File",]]
        if is_elf64():
            gef_print("{:<31s} {:<31s} {:<34s} {:s}".format(*headers))
        else:
            gef_print("{:<23s} {:<23s} {:<23s} {:s}".format(*headers))

        filter_by_file = argv[0] if argv and argv[0] else None
        filter_by_name = argv[1] if len(argv) > 1 and argv[1] else None

        for xfile in get_info_files():
            if filter_by_file:
                if filter_by_file not in xfile.filename:
                    continue
                if filter_by_name and filter_by_name not in xfile.name:
                    continue

            l = []
            l.append(format_address(xfile.zone_start))
            l.append(format_address(xfile.zone_end))
            l.append("{:<21s}".format(xfile.name))
            l.append(xfile.filename)
            gef_print(" ".join(l))
        return


@register_command
class XAddressInfoCommand(GenericCommand):
    """Retrieve and display runtime information for the location(s) given as parameter."""

    _cmdline_ = "xinfo"
    _syntax_  = "{:s} LOCATION".format(_cmdline_)
    _example_ = "{:s} $pc".format(_cmdline_)

    def __init__(self):
        super(XAddressInfoCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke (self, argv):
        if not argv:
            err ("At least one valid address must be specified")
            self.usage()
            return

        for sym in argv:
            try:
                addr = align_address(parse_address(sym))
                gef_print(titlify("xinfo: {:#x}".format(addr)))
                self.infos(addr)

            except gdb.error as gdb_err:
                err("{:s}".format(str(gdb_err)))
        return

    def infos(self, address):
        addr = lookup_address(address)
        if not addr.valid:
            warn("Cannot reach {:#x} in memory space".format(address))
            return

        sect = addr.section
        info = addr.info

        if sect:
            gef_print("Page: {:s} {:s} {:s} (size={:#x})".format(format_address(sect.page_start),
                                                                 RIGHT_ARROW,
                                                                 format_address(sect.page_end),
                                                                 sect.page_end-sect.page_start))
            gef_print("Permissions: {}".format(sect.permission))
            gef_print("Pathname: {:s}".format(sect.path))
            gef_print("Offset (from page): {:#x}".format(addr.value-sect.page_start))
            gef_print("Inode: {:s}".format(sect.inode))

        if info:
            gef_print("Segment: {:s} ({:s}-{:s})".format(info.name,
                                                     format_address(info.zone_start),
                                                     format_address(info.zone_end)))

        sym = gdb_get_location_from_symbol(address)
        if sym:
            name, offset = sym
            msg = "Symbol: {:s}".format(name)
            if offset:
                msg+= "+{:d}".format(offset)
            gef_print(msg)

        return


@register_command
class XorMemoryCommand(GenericCommand):
    """XOR a block of memory. The command allows to simply display the result, or patch it
    runtime at runtime."""

    _cmdline_ = "xor-memory"
    _syntax_  = "{:s} <display|patch> ADDRESS SIZE KEY".format(_cmdline_)

    def __init__(self):
        super(XorMemoryCommand, self).__init__(prefix=True)
        return

    def do_invoke(self, argv):
        self.usage()
        return

@register_command
class XorMemoryDisplayCommand(GenericCommand):
    """Display a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be
    provided in hexadecimal format."""

    _cmdline_ = "xor-memory display"
    _syntax_  = "{:s} ADDRESS SIZE KEY".format(_cmdline_)
    _example_ = "{:s} $sp 16 41414141".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = long(gdb.parse_and_eval(argv[0]))
        length = long(argv[1], 0)
        key = argv[2]
        block = read_memory(address, length)
        info("Displaying XOR-ing {:#x}-{:#x} with {:s}".format(address, address + len(block), repr(key)))

        gef_print(titlify("Original block"))
        gef_print(hexdump(block, base=address))

        gef_print(titlify("XOR-ed block"))
        gef_print(hexdump(xor(block, key), base=address))
        return

@register_command
class XorMemoryPatchCommand(GenericCommand):
    """Patch a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be
    provided in hexadecimal format."""

    _cmdline_ = "xor-memory patch"
    _syntax_  = "{:s} ADDRESS SIZE KEY".format(_cmdline_)
    _example_ = "{:s} $sp 16 41414141".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = parse_address(argv[0])
        length = long(argv[1], 0)
        key = argv[2]
        block = read_memory(address, length)
        info("Patching XOR-ing {:#x}-{:#x} with '{:s}'".format(address, address + len(block), key))
        xored_block = xor(block, key)
        write_memory(address, xored_block, length)
        return


@register_command
class TraceRunCommand(GenericCommand):
    """Create a runtime trace of all instructions executed from $pc to LOCATION specified. The
    trace is stored in a text file that can be next imported in IDA Pro to visualize the runtime
    path."""

    _cmdline_ = "trace-run"
    _syntax_  = "{:s} LOCATION [MAX_CALL_DEPTH]".format(_cmdline_)
    _example_ = "{:s} 0x555555554610".format(_cmdline_)

    def __init__(self):
        super(TraceRunCommand, self).__init__(self._cmdline_, complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_tracing_recursion", 1, "Maximum depth of tracing")
        self.add_setting("tracefile_prefix", "./gef-trace-", "Specify the tracing output file prefix")
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) not in (1, 2):
            self.usage()
            return

        if len(argv) == 2 and argv[1].isdigit():
            depth = long(argv[1])
        else:
            depth = 1

        try:
            loc_start   = current_arch.pc
            loc_end     = long(gdb.parse_and_eval(argv[0]))
        except gdb.error as e:
            err("Invalid location: {:s}".format(e))
            return

        self.trace(loc_start, loc_end, depth)
        return


    def get_frames_size(self):
        n = 0
        f = gdb.newest_frame()
        while f:
            n += 1
            f = f.older()
        return n


    def trace(self, loc_start, loc_end, depth):
        info("Tracing from {:#x} to {:#x} (max depth={:d})".format(loc_start, loc_end,depth))
        logfile = "{:s}{:#x}-{:#x}.txt".format(self.get_setting("tracefile_prefix"), loc_start, loc_end)
        enable_redirect_output(to_file=logfile)
        disable_context()
        self.start_tracing(loc_start, loc_end, depth)
        enable_context()
        disable_redirect_output()
        ok("Done, logfile stored as '{:s}'".format(logfile))
        info("Hint: import logfile with `ida_color_gdb_trace.py` script in IDA to visualize path")
        return


    def start_tracing(self, loc_start, loc_end, depth):
        loc_cur = loc_start
        frame_count_init = self.get_frames_size()

        gef_print("#")
        gef_print("# Execution tracing of {:s}".format(get_filepath()))
        gef_print("# Start address: {:s}".format(format_address(loc_start)))
        gef_print("# End address: {:s}".format(format_address(loc_end)))
        gef_print("# Recursion level: {:d}".format(depth))
        gef_print("# automatically generated by gef.py")
        gef_print("#\n")

        while loc_cur != loc_end:
            try:
                delta = self.get_frames_size() - frame_count_init

                if delta <= depth :
                    gdb.execute("stepi")
                else:
                    gdb.execute("finish")

                loc_cur = current_arch.pc
                gdb.flush()

            except gdb.error as e:
                gef_print("#")
                gef_print("# Execution interrupted at address {:s}".format(format_address(loc_cur)))
                gef_print("# Exception: {:s}".format(e))
                gef_print("#\n")
                break

        return


@register_command
class PatternCommand(GenericCommand):
    """This command will create or search a De Bruijn cyclic pattern to facilitate
    determining the offset in memory. The algorithm used is the same as the one
    used by pwntools, and can therefore be used in conjunction."""

    _cmdline_ = "pattern"
    _syntax_  = "{:s} (create|search) <args>".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(PatternCommand, self).__init__(prefix=True)
        self.add_setting("length", 1024, "Initial length of a cyclic buffer to generate")
        return

    def do_invoke(self, argv):
        self.usage()
        return

@register_command
class PatternCreateCommand(GenericCommand):
    """Generate a de Bruijn cyclic pattern. It will generate a pattern long of SIZE,
    incrementally varying of one byte at each generation. The length of each block is
    equal to sizeof(void*).
    Note: This algorithm is the same than the one used by pwntools library."""

    _cmdline_ = "pattern create"
    _syntax_  = "{:s} [SIZE]".format(_cmdline_)

    def do_invoke(self, argv):
        if len(argv) == 1:
            if not argv[0].isdigit():
                err("Invalid size")
                return
            set_gef_setting("pattern.length", long(argv[0]))
        elif len(argv) > 1:
            err("Invalid syntax")
            return

        size = get_gef_setting("pattern.length")
        info("Generating a pattern of {:d} bytes".format(size))
        pattern_str = gef_pystring(generate_cyclic_pattern(size))
        gef_print(pattern_str)
        ok("Saved as '{:s}'".format( gef_convenience(pattern_str) ))
        return

@register_command
class PatternSearchCommand(GenericCommand):
    """Search for the cyclic de Bruijn pattern generated by the `pattern create` command. The
    PATTERN argument can be a GDB symbol (such as a register name) or an hexadecimal value."""

    _cmdline_ = "pattern search"
    _syntax_  = "{:s} PATTERN [SIZE]".format(_cmdline_)
    _example_ = "\n{0:s} $pc\n{0:s} 0x61616164\n{0:s} aaab".format(_cmdline_)
    _aliases_ = ["pattern offset",]

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc not in (1, 2):
            self.usage()
            return

        if argc==2:
            if not argv[1].isdigit():
                err("Invalid size")
                return
            size = long(argv[1])
        else:
            size = get_gef_setting("pattern.length")

        pattern = argv[0]
        info("Searching '{:s}'".format(pattern))
        self.search(pattern, size)
        return

    def search(self, pattern, size):
        pattern_be, pattern_le = None, None

        # 1. check if it's a symbol (like '$sp' or '0x1337')
        symbol = safe_parse_and_eval(pattern)
        if symbol:
            addr = long(symbol)
            dereferenced_value = dereference(addr)
            # 1-bis. try to dereference
            if dereferenced_value:
                addr = long(dereferenced_value)

            if current_arch.ptrsize == 4:
                pattern_be = struct.pack(">I", addr)
                pattern_le = struct.pack("<I", addr)
            else:
                pattern_be = struct.pack(">Q", addr)
                pattern_le = struct.pack("<Q", addr)

        else:
            # 2. assume it's a plain string
            pattern_be = gef_pybytes(pattern)
            pattern_le = gef_pybytes(pattern[::-1])


        cyclic_pattern = generate_cyclic_pattern(size)
        found = False
        off = cyclic_pattern.find(pattern_le)
        if off >= 0:
            ok("Found at offset {:d} (little-endian search) {:s}".format(off, Color.colorify("likely", attrs="bold red") if is_little_endian() else ""))
            found = True

        off = cyclic_pattern.find(pattern_be)
        if off >= 0:
            ok("Found at offset {:d} (big-endian search) {:s}".format(off, Color.colorify("likely", attrs="bold green") if is_big_endian() else ""))
            found = True

        if not found:
            err("Pattern '{}' not found".format(pattern))
        return


@register_command
class ChecksecCommand(GenericCommand):
    """Checksec the security properties of the current executable or passed as argument. The
    command checks for the following protections:
    - PIE
    - NX
    - RelRO
    - Glibc Stack Canaries
    - Fortify Source"""

    _cmdline_ = "checksec"
    _syntax_  = "{:s} [FILENAME]".format(_cmdline_)
    _example_ = "{} /bin/ls".format(_cmdline_)

    def __init__(self):
        super(ChecksecCommand, self).__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def pre_load(self):
        which("readelf")
        return

    def do_invoke(self, argv):
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

        info("{:s} for '{:s}'".format(self._cmdline_, filename))
        self.print_security_properties(filename)
        return

    def print_security_properties(self, filename):
        sec = checksec(filename)
        for prop in sec:
            if prop in ("Partial RelRO", "Full RelRO"): continue
            val = sec[prop]
            msg = Color.greenify("Yes") if val is True else Color.redify("No")
            if val and prop=="Canary" and is_alive():
                canary = gef_read_canary()[0]
                msg+= "{} value: {:#x}".format(RIGHT_ARROW, canary)

            gef_print("{:<30s}: {:s}".format(prop, msg))

        if sec["Full RelRO"]:
            gef_print("{:<30s}: {:s}".format("RelRO", Color.greenify("Full")))
        elif sec["Partial RelRO"]:
            gef_print("{:<30s}: {:s}".format("RelRO", Color.yellowify("Partial")))
        else:
            gef_print("{:<30s}: {:s}".format("RelRO", Color.redify("No")))
        return


@register_command
class FormatStringSearchCommand(GenericCommand):
    """Exploitable format-string helper: this command will set up specific breakpoints
    at well-known dangerous functions (printf, snprintf, etc.), and check if the pointer
    holding the format string is writable, and therefore susceptible to format string
    attacks if an attacker can control its content."""
    _cmdline_ = "format-string-helper"
    _syntax_ = _cmdline_
    _aliases_ = ["fmtstr-helper",]

    def do_invoke(self, argv):
        dangerous_functions = {
            "printf": 0,
            "sprintf": 1,
            "fprintf": 1,
            "snprintf": 2,
            "vsnprintf": 2,
        }

        enable_redirect_output("/dev/null")

        for func_name, num_arg in dangerous_functions.items():
            FormatStringBreakpoint(func_name, num_arg)

        disable_redirect_output()
        ok("Enabled {:d} FormatStringBreakpoint".format(len(dangerous_functions)))
        return



@register_command
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

    def __init__(self, *args, **kwargs):
        super(HeapAnalysisCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        self.add_setting("check_free_null", False, "Break execution when a free(NULL) is encountered")
        self.add_setting("check_double_free", True, "Break execution when a double free is encountered")
        self.add_setting("check_weird_free", True, "Break execution when free() is called against a non-tracked pointer")
        self.add_setting("check_uaf", True, "Break execution when a possible Use-after-Free condition is found")
        self.add_setting("check_heap_overlap", True, "Break execution when a possible overlap in allocation is found")

        self.bp_malloc, self.bp_calloc, self.bp_free, self.bp_realloc = None, None, None, None
        return

    @only_if_gdb_running
    @experimental_feature
    def do_invoke(self, argv):
        if not argv:
            self.setup()
            return

        if argv[0]=="show":
            self.dump_tracked_allocations()
        return

    def setup(self):
        ok("Tracking malloc() & calloc()")
        self.bp_malloc = TraceMallocBreakpoint("__libc_malloc")
        self.bp_calloc = TraceMallocBreakpoint("__libc_calloc")
        ok("Tracking free()")
        self.bp_free = TraceFreeBreakpoint()
        ok("Tracking realloc()")
        self.bp_realloc = TraceReallocBreakpoint()

        ok("Disabling hardware watchpoints (this may increase the latency)")
        gdb.execute("set can-use-hw-watchpoints 0")

        info("Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.")
        warn("{}: The heap analysis slows down noticeably the execution. ".format(Color.colorify("Note", attrs="bold underline yellow")))

        # when inferior quits, we need to clean everything for a next execution
        gef_on_exit_hook(self.clean)
        return

    def dump_tracked_allocations(self):
        global __heap_allocated_list__, __heap_freed_list__, __heap_uaf_watchpoints__

        if __heap_allocated_list__:
            ok("Tracked as in-use chunks:")
            for addr, sz in __heap_allocated_list__: gef_print("{} malloc({:d}) = {:#x}".format(CROSS, sz, addr))
        else:
            ok("No malloc() chunk tracked")

        if __heap_freed_list__:
            ok("Tracked as free-ed chunks:")
            for addr, sz in __heap_freed_list__: gef_print("{}  free({:d}) = {:#x}".format(TICK, sz, addr))
        else:
            ok("No free() chunk tracked")
        return

    def clean(self, event):
        global __heap_allocated_list__, __heap_freed_list__, __heap_uaf_watchpoints__

        ok("{} - Cleaning up".format(Color.colorify("Heap-Analysis", attrs="yellow bold"),))
        for bp in [self.bp_malloc, self.bp_calloc, self.bp_free, self.bp_realloc]:
            if hasattr(bp, "retbp") and bp.retbp:
                bp.retbp.delete()
            bp.delete()

        for wp in __heap_uaf_watchpoints__:
            wp.delete()

        __heap_allocated_list__ = []
        __heap_freed_list__ = []
        __heap_uaf_watchpoints__ = []

        ok("{} - Re-enabling hardware watchpoints".format(Color.colorify("Heap-Analysis", attrs="yellow bold"),))
        gdb.execute("set can-use-hw-watchpoints 1")

        gef_on_exit_unhook(self.clean)
        return


@register_command
class IsSyscallCommand(GenericCommand):
    """
    Tells whether the next instruction is a system call."""
    _cmdline_ = 'is-syscall'
    _syntax_ = _cmdline_

    def do_invoke(self, argv):
        insn = gef_current_instruction(current_arch.pc)
        ok('Current instruction is{}a syscall'.format(' ' if self.is_syscall(current_arch, insn) else ' not '))

        return

    def is_syscall(self, arch, instruction):
        insn_str = instruction.mnemonic  + ' ' + ', '.join(instruction.operands)
        return insn_str.strip() in arch.syscall_instructions


@register_command
class SyscallArgsCommand(GenericCommand):
    """Gets the syscall name and arguments based on the register values in the current state."""
    _cmdline_ = 'syscall-args'
    _syntax_ = _cmdline_

    def __init__(self):
        super(SyscallArgsCommand, self).__init__()
        self.add_setting("path", os.path.join(GEF_TEMP_DIR, "syscall-tables"),
                         "Path to store/load the syscall tables files")
        return

    def do_invoke(self, argv):
        color = get_gef_setting("theme.xinfo_title_message")

        path = self.get_settings_path()
        if path is None:
            err("Cannot open '{0}': check directory and/or `gef config {0}` setting, "
                "currently: '{1}'".format("syscall-args.path", self.get_setting("path")))
            return

        arch = current_arch.__class__.__name__

        syscall_table = self.get_syscall_table(arch)
        syscall_entry = syscall_table[get_register(current_arch.syscall_register)]

        values = []
        for param in syscall_entry.params:
            values.append(get_register(param.reg))

        parameters = [s.param for s in syscall_entry.params]
        registers = [s.reg for s in syscall_entry.params]

        info("Detected syscall {}".format(Color.colorify(syscall_entry.name, attrs=color)))
        gef_print("    {}({})".format(syscall_entry.name, ', '.join(parameters)));

        headers = [Color.colorify(x, attrs=color) for x in ["Parameter", "Register", "Value"]]
        param_names = [re.split(' |\*', p)[-1] for p in parameters]
        info("{:<28} {:<28} {}".format(*headers))
        for name, register, value in zip(param_names, registers, values):
            line = "    {:<15} {:<15} 0x{:x}".format(name, register, value)

            addrs = DereferenceCommand.dereference_from(value)

            if len(addrs) > 1:
                sep = " {:s} ".format(RIGHT_ARROW)
                line += sep
                line += sep.join(addrs[1:])

            gef_print(line)

        return

    def get_filepath(self, x):
        p = self.get_settings_path()
        if not p: return None
        return os.path.join(p, "{}.py".format(x))

    def get_module(self, modname):
        _fullname = self.get_filepath(modname)
        return imp.load_source(modname, _fullname)

    def get_syscall_table(self, modname):
        _mod = self.get_module(modname)
        return getattr(_mod, 'syscall_table')

    def get_settings_path(self):
        path = os.path.expanduser(self.get_setting("path"))
        path = os.path.realpath(path)
        return path if os.path.isdir(path) else None


class GefCommand(gdb.Command):
    """GEF main command: view all new commands by typing `gef`"""

    _cmdline_ = "gef"
    _syntax_  = "{:s} (missing|config|save|restore|set|run)".format(_cmdline_)

    def __init__(self):
        super(GefCommand, self).__init__(GefCommand._cmdline_,
                                         gdb.COMMAND_SUPPORT,
                                         gdb.COMPLETE_NONE,
                                         True)
        set_gef_setting("gef.follow_child", True, bool, "Automatically set GDB to follow child when forking")
        set_gef_setting("gef.readline_compat", False, bool, "Workaround for readline SOH/ETX issue (SEGV)")
        set_gef_setting("gef.debug", False, bool, "Enable debug mode for gef")
        set_gef_setting("gef.autosave_breakpoints_file", "", str, "Automatically save and restore breakpoints")
        set_gef_setting("gef.extra_plugins_dir", "", str, "Autoload additional GEF commands from external directory")
        set_gef_setting("gef.disable_color", False, bool, "Disable all colors in GEF")
        self.loaded_commands = []
        self.missing_commands = {}
        return

    def setup(self):
        self.load(initial=True)
        # loading GEF sub-commands
        self.doc = GefHelpCommand(self.loaded_commands)
        self.cfg = GefConfigCommand(self.loaded_command_names)
        GefSaveCommand()
        GefRestoreCommand()
        GefMissingCommand()
        GefSetCommand()
        GefRunCommand()

        # load the saved settings
        gdb.execute("gef restore")

        # restore the autosave/autoreload breakpoints policy (if any)
        self.__reload_auto_breakpoints()

        # load plugins from `extra_plugins_dir`
        if self.__load_extra_plugins() > 0:
            # if here, at least one extra plugin was loaded, so we need to restore
            # the settings once more
            gdb.execute("gef restore quiet")

        return


    def __reload_auto_breakpoints(self):
        bkp_fname = __config__.get("gef.autosave_breakpoints_file", None)
        bkp_fname = bkp_fname[0] if bkp_fname else None
        if bkp_fname:
            # restore if existing
            if os.access(bkp_fname, os.R_OK):
                gdb.execute("source {:s}".format(bkp_fname))

            # add hook for autosave breakpoints on quit command
            source = [
                "define hook-quit",
                " save breakpoints {:s}".format(bkp_fname),
                "end"
            ]
            gef_execute_gdb_script("\n".join(source) + "\n")
        return


    def __load_extra_plugins(self):
        nb_added = -1
        try:
            nb_inital = len(self.loaded_commands)
            directories = get_gef_setting("gef.extra_plugins_dir")
            if directories:
                for directory in directories.split(";"):
                    directory = os.path.realpath(os.path.expanduser(directory))
                    if os.path.isdir(directory):
                        sys.path.append(directory)
                        for fname in os.listdir(directory):
                            if not fname.endswith(".py"): continue
                            fpath = "{:s}/{:s}".format(directory, fname)
                            if os.path.isfile(fpath):
                                gdb.execute("source {:s}".format(fpath))
            nb_added = len(self.loaded_commands) - nb_inital
            if nb_added > 0:
                ok("{:s} extra commands added from '{:s}'".format(Color.colorify(str(nb_added), attrs="bold green"),
                                                                  Color.colorify(directory, attrs="bold blue")))
        except gdb.error as e:
            err("failed: {}".format(str(e)))
        return nb_added


    @property
    def loaded_command_names(self):
        return [x[0] for x in self.loaded_commands]


    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("gef help")
        return


    def load(self, initial=False):
        """Load all the commands defined by GEF into GDB."""
        nb_missing = 0
        self.commands = [(x._cmdline_, x) for x in __commands__]

        def is_loaded(x):
            return any(filter(lambda u: x == u[0], self.loaded_commands))

        for cmd, class_name in self.commands:
            if is_loaded(cmd):
                continue

            try:
                self.loaded_commands.append((cmd, class_name, class_name()))

                if hasattr(class_name, "_aliases_"):
                    aliases = getattr(class_name, "_aliases_")
                    for alias in aliases:
                        GefAlias(alias, cmd)

            except Exception as reason:
                self.missing_commands[cmd] = reason
                nb_missing += 1

        # sort by command name
        self.loaded_commands = sorted(self.loaded_commands, key=lambda x: x[1]._cmdline_)

        if initial:
            gef_print("{:s} for {:s} ready, type `{:s}' to start, `{:s}' to configure".format(Color.greenify("GEF"), get_os(),
                                                                                            Color.colorify("gef",attrs="underline yellow"),
                                                                                            Color.colorify("gef config", attrs="underline pink")))

            ver = "{:d}.{:d}".format(sys.version_info.major, sys.version_info.minor)
            nb_cmds = len(self.loaded_commands)
            gef_print("{:s} commands loaded for GDB {:s} using Python engine {:s}".format(Color.colorify(str(nb_cmds), attrs="bold green"),
                                                                                      Color.colorify(gdb.VERSION, attrs="bold yellow"),
                                                                                      Color.colorify(ver, attrs="bold red")))

            if nb_missing:
                warn("{:s} commands could not be loaded, run `{:s}` to know why.".format(Color.colorify(str(nb_missing), attrs="bold red"),
                                                                                         Color.colorify("gef missing", attrs="underline pink")))
        return


class GefHelpCommand(gdb.Command):
    """GEF help sub-command."""
    _cmdline_ = "gef help"
    _syntax_  = _cmdline_

    def __init__(self, commands, *args, **kwargs):
        super(GefHelpCommand, self).__init__(GefHelpCommand._cmdline_,
                                             gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_NONE,
                                             False)
        self.docs = []
        self.generate_help(commands)
        self.refresh()
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gef_print(titlify("GEF - GDB Enhanced Features"))
        gef_print(self.__doc__)
        return

    def generate_help(self, commands):
        """Generate builtin commands documentation."""
        for command in commands:
            self.add_command_to_doc(command)
        return

    def add_command_to_doc(self, command):
        """Add command to GEF documentation."""
        cmd, class_name, _  = command
        if " " in cmd:
            # do not print subcommands in gef help
            return
        doc = getattr(class_name, "__doc__", "").lstrip()
        doc = "\n                         ".join(doc.split("\n"))
        aliases = "(alias: {:s})".format(", ".join(class_name._aliases_)) if hasattr(class_name, "_aliases_") else ""
        w = max(1, get_terminal_size()[1] - 29 - len(aliases))  # use max() to avoid zero or negative numbers
        msg = "{cmd:<25s} -- {help:{w}s} {aliases:s}".format(cmd=cmd, help=Color.greenify(doc), w=w, aliases=aliases)
        self.docs.append(msg)
        return

    def refresh(self):
        """Refresh the documentation."""
        self.__doc__ = "\n".join(sorted(self.docs))
        return


class GefConfigCommand(gdb.Command):
    """GEF configuration sub-command
    This command will help set/view GEF settingsfor the current debugging session.
    It is possible to make those changes permanent by running `gef save` (refer
    to this command help), and/or restore previously saved settings by running
    `gef restore` (refer help).
    """
    _cmdline_ = "gef config"
    _syntax_  = "{:s} [setting_name] [setting_value]".format(_cmdline_)

    def __init__(self, loaded_commands, *args, **kwargs):
        super(GefConfigCommand, self).__init__(GefConfigCommand._cmdline_, gdb.COMMAND_NONE, prefix=False)
        self.loaded_commands = loaded_commands
        return

    def invoke(self, args, from_tty):
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
            names = list(filter(lambda x: x.startswith(prefix), __config__.keys()))
            if names:
                if len(names)==1:
                    gef_print(titlify("GEF configuration setting: {:s}".format(names[0])))
                    self.print_setting(names[0], show_description=True)
                else:
                    gef_print(titlify("GEF configuration settings matching '{:s}'".format(argv[0])))
                    for name in names: self.print_setting(name)
            return

        self.set_setting(argc, argv)
        return

    def print_setting(self, plugin_name, show_description=False):
        res = __config__.get(plugin_name)
        string_color = __config__.get("theme.dereference_string")[0]

        if not res:
            return

        _value, _type, _desc = res
        _setting = Color.colorify(plugin_name, attrs="pink bold underline")
        _type = _type.__name__
        _value = Color.colorify(str(_value), attrs="yellow") if _type!='str' else '"{:s}"'.format(Color.colorify(str(_value), attrs=string_color))
        gef_print("{:s} ({:s}) = {:s}".format(_setting, _type, _value))

        if show_description:
            gef_print("")
            gef_print(Color.colorify("Description:", attrs="bold underline"))
            gef_print("\t{:s}".format(_desc))
        return

    def print_settings(self):
        for x in sorted(__config__):
            self.print_setting(x)
        return

    def set_setting(self, argc, argv):
        global __gef__
        if "." not in argv[0]:
            err("Invalid command format")
            return

        loaded_commands = [ x[0] for x in __gef__.loaded_commands ] + ["gef"]
        plugin_name = argv[0].split(".", 1)[0]
        if plugin_name not in loaded_commands:
            err("Unknown plugin '{:s}'".format(plugin_name))
            return

        _type = __config__.get(argv[0], [None, None, None])[1]
        if _type is None:
            err("Failed to get '{:s}' config setting".format(argv[0],))
            return

        try:
            if _type == bool:
                _newval = True if argv[1].upper() in ("TRUE", "T", "1") else False
            else:
                _newval = _type(argv[1])

        except Exception:
            err("{} expects type '{}'".format(argv[0], _type.__name__))
            return

        __config__[argv[0]][0] = _newval
        return

    def complete(self, text, word):
        settings = sorted(__config__)

        if text=="":
            # no prefix: example: `gef config TAB`
            return [s for s in settings if word in s]

        if "." not in text:
            # if looking for possible prefix
            return [s for s in settings if s.startswith(text.strip())]

        # finally, look for possible values for given prefix
        return [s.split(".", 1)[1] for s in settings if s.startswith(text.strip())]


class GefSaveCommand(gdb.Command):
    """GEF save sub-command
    Saves the current configuration of GEF to disk (by default in file '~/.gef.rc')"""
    _cmdline_ = "gef save"
    _syntax_  = _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefSaveCommand, self).__init__(GefSaveCommand._cmdline_, gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_NONE, False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        cfg = configparser.RawConfigParser()
        old_sect = None

        # save the configuration
        for key in sorted(__config__):
            sect, optname = key.split(".", 1)
            value = __config__.get(key, None)
            value = value[0] if value else None

            if old_sect != sect:
                cfg.add_section(sect)
                old_sect = sect

            cfg.set(sect, optname, value)

        # save the aliases
        cfg.add_section("aliases")
        for alias in __aliases__:
            cfg.set("aliases", alias._alias, alias._command)

        with open(GEF_RC, "w") as fd:
            cfg.write(fd)

        ok("Configuration saved to '{:s}'".format(GEF_RC))
        return


class GefRestoreCommand(gdb.Command):
    """GEF restore sub-command
    Loads settings from file '~/.gef.rc' and apply them to the configuration of GEF"""
    _cmdline_ = "gef restore"
    _syntax_  = _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefRestoreCommand, self).__init__(GefRestoreCommand._cmdline_,
                                                gdb.COMMAND_SUPPORT,
                                                gdb.COMPLETE_NONE,
                                                False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        if not os.access(GEF_RC, os.R_OK):
            return

        quiet = args.lower() == "quiet"
        cfg = configparser.ConfigParser()
        cfg.read(GEF_RC)

        for section in cfg.sections():
            if section == "aliases":
                # load the aliases
                for key in cfg.options(section):
                    GefAlias(key, cfg.get(section, key))
                continue

            # load the other options
            for optname in cfg.options(section):
                try:
                    key = "{:s}.{:s}".format(section, optname)
                    _type = __config__.get(key)[1]
                    new_value = cfg.get(section, optname)
                    if _type == bool:
                        new_value = True if new_value == "True" else False
                    else:
                        new_value = _type(new_value)
                    __config__[key][0] = new_value
                except Exception as e:
                    pass

        if not quiet:
            ok("Configuration from '{:s}' restored".format(Color.colorify(GEF_RC, attrs="bold blue")))
        return


class GefMissingCommand(gdb.Command):
    """GEF missing sub-command
    Display the GEF commands that could not be loaded, along with the reason of why
    they could not be loaded.
    """
    _cmdline_ = "gef missing"
    _syntax_  = _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefMissingCommand, self).__init__(GefMissingCommand._cmdline_,
                                                gdb.COMMAND_SUPPORT,
                                                gdb.COMPLETE_NONE,
                                                False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        missing_commands = __gef__.missing_commands.keys()
        if not missing_commands:
            ok("No missing command")
            return

        for missing_command in missing_commands:
            reason = __gef__.missing_commands[missing_command]
            warn("Command `{}` is missing, reason {} {}".format(missing_command, RIGHT_ARROW, reason))
        return


class GefSetCommand(gdb.Command):
    """Override GDB set commands with the context from GEF.
    """
    _cmdline_ = "gef set"
    _syntax_  = "{:s} [GDB_SET_ARGUMENTS]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefSetCommand, self).__init__(GefSetCommand._cmdline_,
                                            gdb.COMMAND_SUPPORT,
                                            gdb.COMPLETE_SYMBOL,
                                            False)
        return

    def invoke(self, args, from_tty):
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
    Simple wrapper for GDB run command to use arguments set from `gef set args`. """
    _cmdline_ = "gef run"
    _syntax_  = "{:s} [GDB_RUN_ARGUMENTS]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefRunCommand, self).__init__(GefRunCommand._cmdline_,
                                            gdb.COMMAND_SUPPORT,
                                            gdb.COMPLETE_FILENAME,
                                            False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        if is_alive():
            gdb.execute("continue")
            return

        argv = args.split()
        gdb.execute("gef set args {:s}".format(" ".join(argv)))
        gdb.execute("run")
        return


class GefAlias(gdb.Command):
    """Simple aliasing wrapper because GDB doesn't do what it should.
    """
    def __init__(self, alias, command, completer_class=gdb.COMPLETE_NONE, command_class=gdb.COMMAND_NONE):
        p = command.split()
        if not p:
            return

        if list(filter(lambda x: x._alias == alias, __aliases__)):
            return

        self._command = command
        self._alias = alias
        c = command.split()[0]
        r = self.lookup_command(c)
        self.__doc__ = "Alias for '{}'".format(Color.greenify(command))
        if r is not None:
            _instance = r[2]
            self.__doc__ += ": {}".format(_instance.__doc__)

            if hasattr(_instance,  "complete"):
                self.complete = _instance.complete

        super(GefAlias, self).__init__(alias, command_class, completer_class=completer_class)
        __aliases__.append(self)
        return

    def invoke(self, args, from_tty):
        gdb.execute("{} {}".format(self._command, args), from_tty=from_tty)
        return

    def lookup_command(self, cmd):
        global __gef__
        for _name, _class, _instance in __gef__.loaded_commands:
            if cmd == _name:
                return _name, _class, _instance

        return None


class GefAliases(gdb.Command):
    """List all custom aliases."""
    def __init__(self):
        super(GefAliases, self).__init__("aliases", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        ok("Aliases defined:")
        for _alias in __aliases__:
            gef_print("{:30s} {} {}".format(_alias._alias, RIGHT_ARROW, _alias._command))
        return


class GefTmuxSetup(gdb.Command):
    """Setup a confortable tmux debugging environment."""
    def __init__(self):
        super(GefTmuxSetup, self).__init__("tmux-setup", gdb.COMMAND_NONE, gdb.COMPLETE_NONE)
        GefAlias("screen-setup", "tmux-setup")
        return

    def invoke(self, args, from_tty):
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


    def tmux_setup(self):
        """Prepare the tmux environment by vertically splitting the current pane, and
        forcing the context to be redirected there."""
        tmux = which("tmux")
        ok("tmux session found, splitting window...")
        old_ptses = set(os.listdir("/dev/pts"))
        gdb.execute("! {} split-window -h 'clear ; cat'".format(tmux))
        gdb.execute("! {} select-pane -L".format(tmux))
        new_ptses = set(os.listdir("/dev/pts"))
        pty = list(new_ptses - old_ptses)[0]
        pty = "/dev/pts/{}".format(pty)
        ok("Setting `context.redirect` to '{}'...".format(pty))
        gdb.execute("gef config context.redirect {}".format(pty))
        ok("Done!")
        return


    def screen_setup(self):
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
            f.write("screen /bin/bash -c 'tty > {}; clear; cat'\n".format(tty_path))
            f.write("focus left\n")

        gdb.execute("""! {} -r {} -m -d -X source {}""".format(screen, sty, script_path))
        # artificial delay to make sure `tty_path` is populated
        time.sleep(0.25)
        with open(tty_path, "r") as f:
            pty = f.read().strip()
        ok("Setting `context.redirect` to '{}'...".format(pty))
        gdb.execute("gef config context.redirect {}".format(pty))
        ok("Done!")
        os.unlink(script_path)
        os.unlink(tty_path)
        return


def __gef_prompt__(current_prompt):
    """GEF custom prompt function."""
    if get_gef_setting("gef.readline_compat")==True: return GEF_PROMPT
    if get_gef_setting("gef.disable_color")==True: return GEF_PROMPT
    if is_alive(): return GEF_PROMPT_ON
    return GEF_PROMPT_OFF



if __name__  == "__main__":

    if GDB_VERSION < GDB_MIN_VERSION:
        err("You're using an old version of GDB. GEF cannot work correctly. Consider updating to GDB {}.{} or higher.".format(*GDB_MIN_VERSION))

    else:
        # setup prompt
        gdb.prompt_hook = __gef_prompt__

        # setup config
        gdb.execute("set confirm off")
        gdb.execute("set verbose off")
        gdb.execute("set pagination off")
        gdb.execute("set step-mode on")
        gdb.execute("set print elements 0")

        # gdb history
        gdb.execute("set history save on")
        gdb.execute("set history filename ~/.gdb_history")

        # gdb input and output bases
        gdb.execute("set output-radix 0x10")

        # pretty print
        gdb.execute("set print pretty on")

        try:
            # this will raise a gdb.error unless we're on x86
            gdb.execute("set disassembly-flavor intel")
        except gdb.error:
            # we can safely ignore this
            pass

        # SIGALRM will simply display a message, but gdb won't forward the signal to the process
        gdb.execute("handle SIGALRM print nopass")

        # saving GDB indexes in GEF tempdir
        gef_makedirs(GEF_TEMP_DIR)
        gdb.execute("save gdb-index {}".format(GEF_TEMP_DIR))

        # load GEF
        __gef__ = GefCommand()
        __gef__.setup()

        # gdb events configuration
        gef_on_continue_hook(continue_handler)
        gef_on_stop_hook(hook_stop_handler)
        gef_on_new_hook(new_objfile_handler)
        gef_on_exit_hook(exit_handler)

        if gdb.current_progspace().filename is not None:
            # if here, we are sourcing gef from a gdb session already attached
            # we must force a call to the new_objfile handler (see issue #278)
            new_objfile_handler(None)

        GefAliases()
        GefTmuxSetup()
