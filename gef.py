#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#
################################################################################################################
# GEF - Multi-Architecture GDB Enhanced Features for Exploiters & Reverse-Engineers
#
# by  @_hugsy_
#
################################################################################################################
#
# GEF provides additional functions to GDB using its powerful Python API. Some
# functions were inspired by PEDA (https://github.com/longld/peda) which is totally
# awesome *but* is x86 (32/64bits) specific, whereas GEF supports almost all archs
# supported by GDB.
#
# Notes:
# * Since GEF relies on /proc for mapping addresses in memory or other features, it
#   cannot work on hardened configurations (such as GrSec)
# * GEF supports kernel debugging in a limit way (please report crashes & bugs)
#
# Works on
# * x86-32 & x86-64
# * arm v5,v6,v7 & aarch64/armv8 (64b)
# * mips & mips64
# * powerpc & powerpc64
# * sparc & sparc64(v8+)
#
#
# Requires GDB 7.x compiled with Python (2.x, or 3.x)
#
# To start: in gdb, type `source /path/to/gef.py`
#
#
#

from __future__ import print_function

import binascii
import collections
import ctypes
import fcntl
import functools
import getopt
import hashlib
import imp
import itertools
import math
import os
import re
import resource
import socket
import string
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback


if sys.version_info[0] == 2:
    PYTHON_MAJOR = 2

    from HTMLParser import HTMLParser
    from cStringIO import StringIO
    from urllib import urlopen
    import ConfigParser as configparser
    import xmlrpclib

    # Compat Py2/3 hacks
    range = xrange

    left_arrow = "<-"
    right_arrow = "->"
    horizontal_line = "-"
    vertical_line = "|"

elif sys.version_info[0] == 3:
    PYTHON_MAJOR = 3

    from html.parser import HTMLParser
    from io import StringIO
    from urllib.request import urlopen
    import configparser
    import xmlrpc.client as xmlrpclib

    # Compat Py2/3 hack
    long = int
    unicode = str
    FileNotFoundError = IOError

    left_arrow = " \u2190 "
    right_arrow = " \u2192 "
    horizontal_line = "\u2500"
    vertical_line = "\u2502"

else:
    raise Exception("WTF is this Python version??")


def __update_gef(argv):
    gef_local = os.path.realpath(argv[0])
    hash_gef_local = hashlib.sha512( open(gef_local, "rb").read() ).digest()
    gef_remote = "https://raw.githubusercontent.com/hugsy/gef/master/gef.py"
    http = urlopen(gef_remote)
    if http.getcode() != 200:
        print("[-] Failed to get remote gef")
        return 1

    gef_remote_data = http.read()
    hash_gef_remote = hashlib.sha512( gef_remote_data ).digest()

    if hash_gef_local==hash_gef_remote:
        print("[-] No update")
    else:
        with open(gef_local, "wb") as f:
            f.write( gef_remote_data )
        print("[+] Updated")
    return 0


try:
    import gdb
except ImportError:
    # if out of gdb, the only action allowed is to update gef.py
    if len(sys.argv)==2 and sys.argv[1]=="--update":
        sys.exit( __update_gef(sys.argv) )
    print("[-] gef cannot run as standalone")
    sys.exit(0)


__aliases__                            = {}
__config__                             = {}
__infos_files__                        = []
__loaded__                             = []
__missing__                            = {}
__gef_convenience_vars_index__         = 0

DEFAULT_PAGE_ALIGN_SHIFT               = 12
DEFAULT_PAGE_SIZE                      = 1 << DEFAULT_PAGE_ALIGN_SHIFT
GEF_RC                                 = os.getenv("HOME") + "/.gef.rc"


class GefGenericException(Exception):
    def __init__(self, value):
        self.message = value
        return

    def __str__(self):
        return repr(self.message)

class GefMissingDependencyException(GefGenericException):
    pass

class GefUnsupportedMode(GefGenericException):
    pass

class GefUnsupportedOS(GefGenericException):
    pass


class memoize(object):
    """Memoizing class to cache."""
    def __init__(self, f):
        self.func = f
        self.cache = {}
        return

    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            return self.func(*args)

        if args in self.cache:
            return self.cache[args]

        value = self.func(*args)
        self.cache[args] = value
        return value

    def __repr__(self):
        return self.func.__doc__

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)


def reset_all_caches():
    """Free all memoized values."""
    for s in dir(sys.modules['__main__']):
        o = getattr(sys.modules['__main__'], s)
        if hasattr(o, "cache") and len(o.cache)>0:
            o.cache = {}
    return


class Color:
    NORMAL         = "\033[0m"
    GRAY           = "\033[1;30m"
    RED            = "\033[31m"
    GREEN          = "\033[32m"
    YELLOW         = "\033[33m"
    BLUE           = "\033[34m"
    PINK           = "\033[35m"
    BOLD           = "\033[1m"
    UNDERLINE_ON   = "\033[4m"
    UNDERLINE_OFF  = "\033[24m"
    HIGHLIGHT_ON   = "\033[3m"
    HIGHLIGHT_OFF  = "\033[23m"
    BLINK_ON       = "\033[5m"
    BLINK_OFF      = "\033[25m"

    @staticmethod
    def redify(msg):      return Color.colorify(msg, attrs="red")
    @staticmethod
    def greenify(msg):    return Color.colorify(msg, attrs="green")
    @staticmethod
    def blueify(msg):     return Color.colorify(msg, attrs="blue")
    @staticmethod
    def yellowify(msg):   return Color.colorify(msg, attrs="yellow")
    @staticmethod
    def grayify(msg):     return Color.colorify(msg, attrs="gray")
    @staticmethod
    def pinkify(msg):     return Color.colorify(msg, attrs="pink")
    @staticmethod
    def boldify(msg):     return Color.colorify(msg, attrs="bold")
    @staticmethod
    def underlinify(msg): return Color.colorify(msg, attrs="underline")
    @staticmethod
    def highlightify(msg): return Color.colorify(msg, attrs="highlight")
    @staticmethod
    def blinkify(msg): return Color.colorify(msg, attrs="blink")

    @staticmethod
    def colorify(msg, attrs):
        if __config__["gef.no_color"][0]:
            return msg
        m = []
        for attr in attrs.split():
            if   attr == "bold":       m.append(Color.BOLD)
            elif attr == "underline":  m.append(Color.UNDERLINE_ON)
            elif attr == "highlight":  m.append(Color.HIGHLIGHT_ON)
            elif attr == "blink":      m.append(Color.BLINK_ON)
            elif attr == "red":        m.append(Color.RED)
            elif attr == "green":      m.append(Color.GREEN)
            elif attr == "blue":       m.append(Color.BLUE)
            elif attr == "yellow":     m.append(Color.YELLOW)
            elif attr == "gray":       m.append(Color.GRAY)
            elif attr == "pink":       m.append(Color.PINK)
        m.append(msg)
        if   Color.HIGHLIGHT_ON in m :   m.append(Color.HIGHLIGHT_OFF)
        elif Color.UNDERLINE_ON in m :   m.append(Color.UNDERLINE_OFF)
        elif Color.BLINK_ON in m :       m.append(Color.BLINK_OFF)
        m.append(Color.NORMAL)
        return "".join(m)


class Address:
    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
        self.section = kwargs.get("section", None)
        self.info = kwargs.get("info", None)
        return

    def __str__(self):
        return hex( self.value )

    def is_in_text_segment(self):
        return hasattr(self.info, "name") and ".text" in self.info.name

    def is_in_stack_segment(self):
        return hasattr(self.info, "name") and "[stack]" in self.info.name

    def is_in_heap_segment(self):
        return hasattr(self.info, "name") and "[heap]" in self.info.name

    def dereference(self):
        addr = align_address(long(self.value))
        addr = dereference(addr)
        return long(addr)


class Permission:
    NONE      = 0
    READ      = 1
    WRITE     = 2
    EXECUTE   = 4
    ALL       = READ | WRITE | EXECUTE

    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
        return

    def __or__(self, a):
        return self.value | a

    def __and__(self, a):
        return self.value & a

    def __xor__(self, a):
        return self.value ^ a

    def __eq__(self, a):
        return self.value == a

    def __ne__(self, a):
        return self.value != a

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    @staticmethod
    def from_info_sections(*args):
        p = Permission()
        for arg in args:
            if "READONLY" in arg:
                p.value += Permission.READ
            if "DATA" in arg:
                p.value += Permission.WRITE
            if "CODE" in arg:
                p.value += Permission.EXECUTE
        return p

    @staticmethod
    def from_process_maps(perm_str):
        p = Permission()
        if perm_str[0] == "r":
            p.value += Permission.READ
        if perm_str[1] == "w":
            p.value += Permission.WRITE
        if perm_str[2] == "x":
            p.value += Permission.EXECUTE
        return p


class Section:
    page_start      = None
    page_end        = None
    offset          = None
    permission      = None
    inode           = None
    path            = None

    def __init__(self, *args, **kwargs):
        attrs = ["page_start", "page_end", "offset", "permission", "inode", "path"]
        for attr in attrs:
            value = kwargs[attr] if attr in kwargs else None
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


class Zone:
    name              = None
    zone_start        = None
    zone_end          = None
    filename          = None


class Elf:
    """
    Basic ELF parsing based on http://www.skyfree.org/linux/references/ELF_Format.pdf
    """
    e_magic           = None
    e_class           = None
    e_endianness      = None
    e_eiversion       = None
    e_osabi           = None
    e_abiversion      = None
    e_pad             = None
    e_type            = None
    e_machine         = None
    e_version         = None
    e_entry           = None
    e_phoff           = None
    e_shoff           = None
    e_flags           = None
    e_ehsize          = None
    e_phentsize       = None
    e_phnum           = None
    e_shentsize       = None
    e_shnum           = None
    e_shstrndx        = None

    BIG_ENDIAN        = 0
    LITTLE_ENDIAN     = 1


    def __init__(self, elf):

        if not os.access(elf, os.R_OK):
            err("'{0}' not found/readable".format(elf))
            err("Failed to get file debug information, most of gef features will not work")
            return

        with open(elf, "rb") as f:
            # off 0x0
            self.e_magic, self.e_class, self.e_endianness, self.e_eiversion = struct.unpack(">IBBB", f.read(7))

            # adjust endianness in bin reading
            if self.e_endianness == Elf.LITTLE_ENDIAN:
                endian = "<" # LE
            else:
                endian = ">" # BE

            # off 0x7
            self.e_osabi, self.e_abiversion = struct.unpack(endian + "BB", f.read(2))
            # off 0x9
            self.e_pad = f.read(7)
            # off 0x10
            self.e_type, self.e_machine, self.e_version = struct.unpack(endian + "HHI", f.read(8))
            # off 0x18
            if self.e_class == 0x02:
                # if arch 64bits
                self.e_entry, self.e_phoff, self.e_shoff = struct.unpack(endian + "QQQ", f.read(24))
            else:
                # else arch 32bits
                self.e_entry, self.e_phoff, self.e_shoff = struct.unpack(endian + "III", f.read(12))

            self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum = struct.unpack(endian + "HHHH", f.read(8))
            self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack(endian + "HHH", f.read(6))

        return


class GlibcArena:
    """
    Glibc arena class
    Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671
    """
    def __init__(self, addr=None):
        #
        arena = gdb.parse_and_eval(addr)
        self.__arena = arena.cast(gdb.lookup_type("struct malloc_state"))
        self.__addr = long(arena.address)
        self.__arch = long(get_memory_alignment(to_byte=True))
        return

    def __getitem__(self, item):
        return self.__arena[item]

    def __getattr__(self, item):
        return self.__arena[item]

    def __int__(self):
        return self.__addr

    def deref_as_long(self, addr):
        naddr = dereference(addr).address
        return long(naddr)

    def fastbin(self, i):
        addr = self.deref_as_long(self.fastbinsY[i])
        if addr == 0x00:
            return None
        return GlibcChunk(addr+2*self.__arch)

    def bin(self, i):
        idx = i * 2
        fd = self.deref_as_long(self.bins[idx])
        bw = self.deref_as_long(self.bins[idx+1])
        return (fd, bw)

    def get_next(self):
        addr_next = self.deref_as_long(self.next)
        arena_main = GlibcArena("main_arena")
        if addr_next == arena_main.__addr:
            return None
        addr_next = "*0x%x " % addr_next
        return GlibcArena(addr_next)

    def get_arch(self):
        return self.__arch

    def __str__(self):
        top             = self.deref_as_long(self.top)
        last_remainder  = self.deref_as_long(self.last_remainder)
        n               = self.deref_as_long(self.next)
        nfree           = self.deref_as_long(self.next_free)
        sysmem          = long(self.system_mem)
        m = "Arena ("
        m+= "base={:#x},".format(self.__addr)
        m+= "top={:#x},".format(top)
        m+= "last_remainder={:#x},".format(last_remainder)
        m+= "next={:#x},".format(n)
        m+= "next_free={:#x},".format(nfree)
        m+= "system_mem={:#x}".format(sysmem)
        m+= ")"
        return m


class GlibcChunk:
    """ Glibc chunk class.
    Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/"""

    def __init__(self, addr, from_base=False):
        """Init `addr` as a chunk"""
        self.arch = int(get_memory_alignment(to_byte=True))
        if from_base:
            self.start_addr = addr
            self.addr = addr + 2*self.arch
        else:
            self.start_addr = int(addr - 2*self.arch)
            self.addr = addr

        self.size_addr  = int(self.addr - self.arch)
        self.prev_size_addr = self.start_addr
        return


    def get_chunk_size(self):
        return read_int_from_memory( self.size_addr ) & (~0x03)


    def get_usable_size(self):
        # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4537
        cursz = self.get_chunk_size()
        if cursz == 0x00: return cursz
        if self.has_M_bit(): return cursz - 2*self.arch
        return cursz - self.arch

    def get_prev_chunk_size(self):
        return read_int_from_memory( self.prev_size_addr )


    def get_next_chunk(self):
        addr = self.addr + self.get_chunk_size()
        return GlibcChunk(addr)


    # if free-ed functions
    def get_fwd_ptr(self):
        return read_int_from_memory( self.addr )

    def get_bkw_ptr(self):
        return read_int_from_memory( self.addr+self.arch )
    # endif free-ed functions


    def has_P_bit(self):
        """Check for in PREV_INUSE bit
        Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1267"""
        return read_int_from_memory( self.size_addr ) & 0x01

    def has_M_bit(self):
        """Check for in IS_MMAPPED bit
        Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1274"""
        return read_int_from_memory( self.size_addr ) & 0x02

    def has_N_bit(self):
        """Check for in NON_MAIN_ARENA bit.
        Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1283"""
        return read_int_from_memory( self.size_addr ) & 0x04

    def is_used(self):
        """
        Check if the current block is used by:
        - checking the M bit is true
        - or checking that next chunk PREV_INUSE flag is true
        """
        if self.has_M_bit():
            return True

        next_chunk = self.get_next_chunk()
        return True if next_chunk.has_P_bit() else False


    def str_chunk_size_flag(self):
        msg = ""
        msg+= "PREV_INUSE flag: "
        msg+= Color.greenify("On") if self.has_P_bit() else Color.redify("Off")
        msg+= "\n"

        msg+= "IS_MMAPPED flag: "
        msg+= Color.greenify("On") if self.has_M_bit() else Color.redify("Off")
        msg+= "\n"

        msg+= "NON_MAIN_ARENA flag: "
        msg+= Color.greenify("On") if self.has_N_bit() else Color.redify("Off")

        return msg


    def _str_sizes(self):
        msg = ""
        failed = False

        try:
            msg+= "Chunk size: {0:d} ({0:#x})\n".format( self.get_chunk_size() )
            msg+= "Usable size: {0:d} ({0:#x})\n".format( self.get_usable_size() )
            failed = True
        except gdb.MemoryError as me:
            msg+= "Chunk size: Cannot read at {0:#x} (corrupted?)\n".format(self.size_addr)

        try:
            msg+= "Previous chunk size: {0:d} ({0:#x})\n".format( self.get_prev_chunk_size() )
            failed = True
        except gdb.MemoryError as me:
            msg+= "Previous chunk size: Cannot read at {0:#x} (corrupted?)\n".format(self.start_addr)

        if failed:
            msg+= self.str_chunk_size_flag()

        return msg

    def _str_pointers(self):
        fwd = self.addr
        bkw = self.addr + self.arch

        msg = ""

        try:
            msg+= "Forward pointer: {0:#x}\n".format( self.get_fwd_ptr() )
        except gdb.MemoryError as me:
            msg+= "Forward pointer: {0:#x} (corrupted?)\n".format( fwd )

        try:
            msg+= "Backward pointer: {0:#x}\n".format( self.get_bkw_ptr() )
        except gdb.MemoryError as me:
            msg+= "Backward pointer: {0:#x} (corrupted?)\n".format( bkw )

        return msg

    def str_as_alloced(self):
        return self._str_sizes()

    def str_as_freeed(self):
        return self._str_sizes() + '\n'*2 + self._str_pointers()

    def __str__(self):
        m = ""
        m+= Color.greenify("FreeChunk") if not self.is_used() else Color.redify("UsedChunk")
        m+= "(addr={:#x},size={:#x})".format(long(self.addr),self.get_chunk_size())
        return m

    def pprint(self):
        msg = ""
        if not self.is_used():
            msg += titlify("Chunk (free): %#x" % self.start_addr, Color.GREEN)
            msg += "\n"
            msg += self.str_as_freeed()
        else:
            msg += titlify("Chunk (used): %#x" % self.start_addr, Color.RED)
            msg += "\n"
            msg += self.str_as_alloced()

        gdb.write(msg+"\n")
        gdb.flush()
        return


def titlify(msg, color=Color.RED):
    cols = get_terminal_size()[1]
    n = int((cols-len(msg)-4)/2)
    if color==Color.RED:
        title = Color.colorify(msg, attrs="bold red")
    elif color==Color.GREEN:
        title = Color.colorify(msg, attrs="bold green")
    return "{0}[ {1} ]{0}".format(horizontal_line*n, title)

def _xlog(m, stream, cr=True):
    m += "\n" if cr else ""
    gdb.write(m, stream)
    gdb.flush()
    return 0

def err(msg, cr=True):   return _xlog(Color.colorify("[!]", attrs="bold red")+" "+msg, gdb.STDERR, cr)
def warn(msg, cr=True):  return _xlog(Color.colorify("[*]", attrs="bold yellow")+" "+msg, gdb.STDLOG, cr)
def ok(msg, cr=True):    return _xlog(Color.colorify("[+]", attrs="bold green")+" "+msg, gdb.STDLOG, cr)
def info(msg, cr=True):  return _xlog(Color.colorify("[+]", attrs="bold blue")+" "+msg, gdb.STDLOG, cr)


def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    raise IOError("Missing file `%s`" % program)


def hexdump(source, length=0x10, separator='.', show_raw=False, base=0x00):
    """
    Return the hexdump of `src` argument.
    @param source *MUST* be of type bytes or bytearray
    @param length is the length of items per line
    @param separator is the default character to use if one byte is not printable
    @param show_raw if True, do not add the line nor the text translation
    @param base is the start address of the block being hexdump
    @param func is the function to use to parse bytes (int for Py3, chr for Py2)
    @return a string with the hexdump
    """
    result = []
    for i in range(0, len(source), length):
        s = source[i:i+length]

        if PYTHON_MAJOR == 3:
            hexa = ' '.join(["%02X" % c for c in s])
            text = ''.join( [chr(c) if 0x20 <= c < 0x7F else separator for c in s] )
        else:
            hexa = ' '.join(["%02X" % ord(c) for c in s])
            text = ''.join( [c if 0x20 <= ord(c) < 0x7F else separator for c in s] )

        if show_raw:
            result.append(hexa)
        else:
            result.append( "%#-.*x     %-*s    %s" % (16, base+i, 3*length, hexa, text) )

    return '\n'.join(result)


def is_debug():
    return "global.debug" in __config__.keys() and __config__["global.debug"][0]==True


def enable_debug():
    __config__["global.debug"] = (True, bool)
    return


def disable_debug():
    __config__["global.debug"] = (False, bool)
    return


def disable_output(to_file="/dev/null"):
    gdb.execute("set logging overwrite")
    gdb.execute("set logging file %s" % to_file)
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")
    return


def enable_output():
    gdb.execute( "set logging redirect off" )
    gdb.execute( "set logging off" )
    return


def gef_makedirs(path, mode=0o755):
    if PYTHON_MAJOR == 3:
        os.makedirs(path, mode=mode, exist_ok=True)
        return
    try:
        os.makedirs(path, mode=mode)
    except os.error:
        pass
    return


def gef_obsolete_function(func):
    def new_func(*args, **kwargs):
        warn("Call to deprecated function '{}'.".format(func.__name__))
        return func(*args, **kwargs)
    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    new_func.__dict__.update(func.__dict__)
    return new_func


def _gef_disassemble_top(addr, nb_insn):
    lines = gdb.execute("x/%di %#x" % (nb_insn, addr), to_string=True).splitlines()
    lines = [ re.sub(r'(\t|:)', r' ', x.replace("=>", "").strip()) for x in lines ]
    return lines


def _gef_disassemble_around(addr, nb_insn):
    """
    Adjust lines to disassemble because of variable length instructions architecture (intel)
    """
    lines = []

    if not ( is_x86_32() or is_x86_64() ):
        # all ABI except x86 are fixed length instructions, easy to process
        insn_len = 4 if is_aarch64() or is_ppc64() else get_memory_alignment(to_byte=True)
        top = addr - (nb_insn-3)*insn_len*2
        lines = _gef_disassemble_top(top,  nb_insn-1)
        lines+= _gef_disassemble_top(addr, nb_insn)
        return lines

    cur_insn = gdb.execute("x/1i %#x" % addr, to_string=True).splitlines()[0]
    found = False

    # we try to find a good set of previous instructions by guessing incrementally
    for i in reversed( range(255) ):
        try:
            cmd = "x/%di %#x" % (nb_insn, addr-i)
            lines = gdb.execute(cmd, to_string=True).splitlines()
        except gdb.MemoryError as me:
            # we can hit an unmapped page trying to read backward, if so just print forward disass lines
            break

        # 1. check no bad instructions in found
        if any( map(lambda x: "(bad)" in x, lines) ):
            continue

        # 2. if cur_insn is not in the "middle" of the set, it is invalid
        insn = lines[-1]
        if insn != cur_insn:
            continue

        # we assume here that it was successful
        found = True
        lines = [ re.sub(r'(\t|:)', r' ', x.replace("=>", "").strip()) for x in lines[-nb_insn:-1] ]
        break

    if not found:
        lines = []

    lines += _gef_disassemble_top(addr, nb_insn)
    return lines


def gef_disassemble(addr, nb_insn, from_top=False):
    if nb_insn % 2 == 0: nb_insn += 1
    if from_top:
        lines = _gef_disassemble_top(addr, nb_insn)
    else:
        lines = _gef_disassemble_around(addr, nb_insn)

    if len(lines)==0: return []
    result = []
    for line in lines:
        (address, location, mnemo, operands) = gef_parse_gdb_instruction(line)
        code = "%s     %s   %s" % (location, mnemo, ','.join(operands))
        result.append( (address, code) )
    return result


def gef_parse_gdb_instruction(raw_insn):
    patt = re.compile(r'^(0x[0-9a-f]{,16})(.*)$', flags=re.IGNORECASE)
    parts = [ x for x in re.split(patt, raw_insn) if len(x)>0 ]
    address = int(parts[0], 16)
    code = parts[1].strip()
    parts = code.split()
    if code.startswith("<"):
        location = re.sub(r'<([^>]*)>:', r'\1', parts[0])
        mnemo = parts[1]
        operands = " ".join(parts[2:])
    else:
        location = ""
        mnemo = parts[0]
        operands = " ".join(parts[1:])
    operands = operands.split(',')
    return (address, location, mnemo, operands)


def gef_execute_external(command, *args, **kwargs):
    res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=kwargs.get("shell", False))

    if kwargs.get("as_list", False) == True:
        return res.splitlines()

    if PYTHON_MAJOR == 3:
        return str(res, encoding="ascii" )

    return res


def get_frame():
    return gdb.selected_inferior()


@memoize
def get_arch():
    return gdb.execute("show architecture", to_string=True).strip().split()[7][:-1]

@memoize
def get_endian():
    if gdb.execute("show endian", to_string=True).strip().split()[7] == "little" :
        return Elf.LITTLE_ENDIAN
    return Elf.BIG_ENDIAN

def is_big_endian():
    return get_endian() == Elf.BIG_ENDIAN

def is_little_endian():
    return not is_big_endian()

def flags_to_human(reg_value, value_table):
    flags = "["
    for i in value_table.keys():
        w = Color.boldify( value_table[i].upper() ) if reg_value & (1<<i) else value_table[i].lower()
        flags += " %s " % w
    flags += "]"
    return flags


######################[ ARM specific ]######################
@memoize
def arm_registers():
    return ["$r0   ", "$r1   ", "$r2   ", "$r3   ", "$r4   ", "$r5   ", "$r6   ",
            "$r7   ", "$r8   ", "$r9   ", "$r10  ", "$r11  ", "$r12  ", "$sp   ",
            "$lr   ", "$pc   ", "$cpsr ", ]

@memoize
def arm_nop_insn():
    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0041c/Caccegih.html
    # return b"\x00\x00\xa0\xe1" # mov r0,r0
    return b"\x01\x10\xa0\xe1" # mov r1,r1

@memoize
def arm_return_register():
    return "$r0"

@memoize
def arm_flag_register():
    return "$cpsr"

@memoize
def arm_flags_table():
    table = { 31: "negative",
              30: "zero",
              29: "carry",
              28: "overflow",
              7: "interrupt",
              6: "fast",
              5: "thumb"
    }
    return table

def arm_flags_to_human(val=None):
    # http://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
    if val is None:
        reg = arm_flag_register()
        val = get_register_ex( reg )
    return flags_to_human(val, arm_flags_table())

def arm_is_cbranch(insn):
    mnemo = ["bl", "blr", "blx", ]
    return any(filter(lambda x: x == insn, mnemo))

def arm_is_cbranch(insn):
    mnemo = ["beq", "bne", "bleq", "blt", "bgt", "bgez", "bvs", "bvc",
             "jeq", "jne", "jleq", "jlt", "jgt", "jgez", "jvs", "jvc"]
    return any(filter(lambda x: x == insn, mnemo))

def arm_is_branch_taken(mnemo):
    # ref: http://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
    flags = dict( (arm_flags_table()[k], k) for k in arm_flags_table().keys() )
    val = get_register_ex(arm_flag_register() )

    if mnemo.endswith("eq"): return val&(1<<flags["zero"]), "Z"
    if mnemo.endswith("ne"): return val&(1<<flags["zero"])==0, "!Z"
    if mnemo.endswith("lt"): return val&(1<<flags["negative"])!=val&(1<<flags["overflow"]), "N!=O"
    if mnemo.endswith("le"): return val&(1<<flags["zero"]) or val&(1<<flags["negative"])!=val&(1<<flags["overflow"]), "Z || N!=O"
    if mnemo.endswith("gt"): return val&(1<<flags["zero"])==0 and val&(1<<flags["negative"])==val&(1<<flags["overflow"]), "!Z && N==O"
    if mnemo.endswith("ge"): return val&(1<<flags["negative"])==val&(1<<flags["overflow"]), "N==O"
    if mnemo.endswith("bvs"): return val&(1<<flags["overflow"]), "O"
    if mnemo.endswith("bvc"): return val&(1<<flags["overflow"])==0, "O"
    return False, ""

@memoize
def arm_function_parameters():
    return ['$r0','$r1','$r2','$r3']


######################[ Intel x86-64 specific ]######################
@memoize
def x86_64_registers():
    return [ "$rax   ", "$rbx   ", "$rcx   ", "$rdx   ", "$rsp   ", "$rbp   ", "$rsi   ",
             "$rdi   ", "$rip   ", "$r8    ", "$r9    ", "$r10   ", "$r11   ", "$r12   ",
             "$r13   ", "$r14   ", "$r15   ",
             "$cs    ", "$ss    ", "$ds    ", "$es    ", "$fs    ", "$gs    ", "$eflags", ]

@memoize
def x86_64_nop_insn():
    return b'\x90'

@memoize
def x86_64_return_register():
    return "$rax"

@memoize
def x86_64_function_parameters():
    return ['$rdi', '$rsi', '$rdx', '$rcx', '$r8', '$r9']

@memoize
def x86_flag_register():
    return "$eflags"

@memoize
def x86_flags_table():
    table = { 6: "zero",
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
    return table

def x86_flags_to_human(val=None):
    reg = x86_flag_register()
    if not val:
        val = get_register_ex( reg )
    return flags_to_human(val, x86_flags_table())

def x86_is_call(insn):
    mnemo = ["call", "callq", ]
    return any( filter(lambda x: x == insn, mnemo) )

def x86_is_cbranch(insn):
    mnemo = ["ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
             "jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
             "jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
             "jo", "jp", "jpe", "js",]
    return any( filter(lambda x: x == insn, mnemo) )

def x86_is_branch_taken(mnemo):
    # all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
    flags = dict( (x86_flags_table()[k], k) for k in x86_flags_table().keys() )
    val = get_register_ex(x86_flag_register() )
    cx = get_register_ex("$rcx") if is_x86_64() else get_register_ex("$ecx")

    if mnemo in ("ja", "jnbe"): return val&(1<<flags["carry"])==0 and val&(1<<flags["zero"])==0, "!C && !Z"
    if mnemo in ("jae", "jnb", "jnc"): return val&(1<<flags["carry"])==0, "!C"
    if mnemo in ("jb", "jc", "jnae"): return val&(1<<flags["carry"]), "C"
    if mnemo in ("jbe", "jna"): return val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "C || Z"
    if mnemo in ("jcxz", "jecxz", "jrcxz"): return cx==0, "!$CX"
    if mnemo in ("je", "jz"): return val&(1<<flags["zero"]), "Z"
    if mnemo in ("jg", "jnle"): return val&(1<<flags["zero"])==0 and val&(1<<flags["overflow"])==val&(1<<flags["sign"]), "!Z && O==S"
    if mnemo in ("jge", "jnl"): return val&(1<<flags["sign"])==val&(1<<flags["overflow"]), "S==O"
    if mnemo in ("jl", "jnge"): return val&(1<<flags["overflow"])!=val&(1<<flags["sign"]), "S!=O"
    if mnemo in ("jle", "jng"): return val&(1<<flags["zero"]) or val&(1<<flags["overflow"])!=val&(1<<flags["sign"]), "Z || S!=0"
    if mnemo in ("jne", "jnz"): return val&(1<<flags["zero"])==0, "!Z"
    if mnemo in ("jno"): return val&(1<<flags["overflow"])==0, "!O"
    if mnemo in ("jnp", "jpo"): return val&(1<<flags["parity"])==0, "!P"
    if mnemo in ("jns"): return val&(1<<flags["sign"])==0, "!S"
    if mnemo in ("jo"): return val&(1<<flags["overflow"]), "O"
    if mnemo in ("jpe", "jp"): return val&(1<<flags["parity"]), "P"
    if mnemo in ("js"): return val&(1<<flags["sign"]), "S"
    return False, ""

######################[ Intel x86-32 specific ]######################
@memoize
def x86_32_registers():
    return [ "$eax   ", "$ebx   ", "$ecx   ", "$edx   ", "$esp   ", "$ebp   ", "$esi   ",
             "$edi   ", "$eip   ", "$cs    ", "$ss    ", "$ds    ", "$es    ",
             "$fs    ", "$gs    ", "$eflags", ]

@memoize
def x86_32_return_register():
    return "$eax"

@memoize
def x86_32_function_parameters():
    return ["$esp",]


######################[ PowerPC specific ]######################
@memoize
def powerpc_registers():
    return ["$r0  ", "$r1  ", "$r2  ", "$r3  ", "$r4  ", "$r5  ", "$r6  ", "$r7  ",
            "$r8  ", "$r9  ", "$r10 ", "$r11 ", "$r12 ", "$r13 ", "$r14 ", "$r15 ",
            "$r16 ", "$r17 ", "$r18 ", "$r19 ", "$r20 ", "$r21 ", "$r22 ", "$r23 ",
            "$r24 ", "$r25 ", "$r26 ", "$r27 ", "$r28 ", "$r29 ", "$r30 ", "$r31 ",
            "$pc  ", "$msr ", "$cr  ", "$lr  ", "$ctr ", "$xer ", "$trap" ]

@memoize
def powerpc_nop_insn():
    # http://www.ibm.com/developerworks/library/l-ppc/index.html
    # nop
    return b'\x60\x00\x00\x00'

@memoize
def powerpc_return_register():
    return "$r0"

@memoize
def powerpc_flag_register():
    return "$cr"

@memoize
def powerpc_flags_table():
    table = { 0: "negative",
              1: "positive",
              2: "zero",
              3: "summary",
              28: "less",
              29: "greater",
              30: "equal",
              31: "overflow",
    }
    return table

def powerpc_flags_to_human(val=None):
    # http://www.cebix.net/downloads/bebox/pem32b.pdf (% 2.1.3)
    if not val:
        reg = powerpc_flag_register()
        val = get_register_ex( reg )
    return flags_to_human(val, powerpc_flags_table())

def powerpc_is_call(insn):
    return False

def powerpc_is_cbranch(insn):
    mnemo = ["beq", "bne", "ble", "blt", "bgt", "bge", ]
    return any( filter(lambda x: x == insn, mnemo) )

def powerpc_is_branch_taken(mnemo):
    flags = dict( (powerpc_flags_table()[k], k) for k in powerpc_flags_table().keys() )
    val = get_register_ex(powerpc_flag_register())
    if mnemo=="beq": return val&(1<<flags["equal"]), "E"
    if mnemo=="bne": return val&(1<<flags["equal"])==0, "!E"
    if mnemo=="ble": return val&(1<<flags["equal"]) or val&(1<<flags["less"]), "E || L"
    if mnemo=="blt": return val&(1<<flags["less"]), "L"
    if mnemo=="bge": return val&(1<<flags["equal"]) or val&(1<<flags["greater"]), "E || G"
    if mnemo=="bgt": return val&(1<<flags["greater"]), "G"
    return False, ""

@memoize
def powerpc_function_parameters():
    return ['$r3', '$r4', '$r4','$r5', '$r6']


######################[ SPARC specific ]######################
@memoize
def sparc_registers():
    return ["$g0 ", "$g1 ", "$g2 ", "$g3 ", "$g4 ", "$g5 ", "$g6 ", "$g7 ",
            "$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ", "$o7 ",
            "$l0 ", "$l1 ", "$l2 ", "$l3 ", "$l4 ", "$l5 ", "$l6 ", "$l7 ",
            "$i0 ", "$i1 ", "$i2 ", "$i3 ", "$i4 ", "$i5 ", "$i7 ",
            "$pc ", "$npc", "$sp ", "$fp ", "$psr", ]

@memoize
def sparc_nop_insn():
    # http://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf
    # sethi 0, %g0
    return b'\x00\x00\x00\x00'

@memoize
def sparc_return_register():
    return "$i0"

@memoize
def sparc_flag_register():
    return "$psr"

@memoize
def sparc_flags_table():
    table = { 23: "negative",
              20: "carry",
              22: "zero",
              5: "trap",
              7: "supervisor",
              21: "overflow",
    }
    return table

def sparc_flags_to_human(val=None):
    # http://www.gaisler.com/doc/sparcv8.pdf
    reg = sparc_flag_register()
    if not val:
        val = get_register_ex( reg )
    return flags_to_human(val, sparc_flags_table())

def sparc_is_call(insn):
    return False

def sparc_is_cbranch(insn):
    # http://moss.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/condbranch.html
    mnemo = ["be", "bne", "bg", "bge", "bgeu", "bgu", "bl", "ble", "blu", "bleu",
             "bneg", "bpos", "bvs", "bvc", "bcs", "bcc", ]
    return any( filter(lambda x: x == insn, mnemo) )

def sparc_is_branch_taken(insn):
    flags = dict( (sparc_flags_table()[k], k) for k in sparc_flags_table().keys() )
    val = get_register_ex(sparc_flag_register())
    if insn=="be": return val&(1<<flags["zero"]), "Z"
    if insn=="bne": return val&(1<<flags["zero"])==0, "!Z"
    if insn=="bg": return val&(1<<flags["zero"])==0 and (val&(1<<flags["negative"])==0 or val&(1<<flags["overflow"])==0), "!Z && (!N || !O)"
    if insn=="bge": return val&(1<<flags["negative"])==0 or val&(1<<flags["overflow"])==0, "!N || !O"
    if insn=="bgu": return val&(1<<flags["carry"])==0 and val&(1<<flags["zero"])==0, "!C && !C"
    if insn=="bgeu": return val&(1<<flags["carry"])==0, "!C"
    if insn=="bl": return val&(1<<flags["negative"]) and val&(1<<flags["overflow"]), "N && O"
    if insn=="blu": return val&(1<<flags["carry"]), "C"
    if insn=="ble": return val&(1<<flags["zero"]) or (val&(1<<flags["negative"]) or val&(1<<flags["overflow"])), "Z || (N || O)"
    if insn=="bleu": return val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "C || Z"
    if insn=="bneg": return val&(1<<flags["negative"]), "N"
    if insn=="bpos": return val&(1<<flags["negative"])==0, "!N"
    if insn=="bvs": return val&(1<<flags["overflow"]), "O"
    if insn=="bvc": return val&(1<<flags["overflow"])==0, "!O"
    if insn=="bcs": return val&(1<<flags["carry"]), "C"
    if insn=="bcc": return val&(1<<flags["carry"])==0, "!C"
    return False, ""

@memoize
def powerpc_function_parameters():
    return ['$i0', '$i1', '$i2','$i3','$i4', '$i5' ]


######################[ MIPS specific ]######################
@memoize
def mips_registers():
    # http://vhouten.home.xs4all.nl/mipsel/r3000-isa.html
    return ["$zero     ", "$at       ", "$v0       ", "$v1       ", "$a0       ", "$a1       ", "$a2       ", "$a3       ",
            "$t0       ", "$t1       ", "$t2       ", "$t3       ", "$t4       ", "$t5       ", "$t6       ", "$t7       ",
            "$s0       ", "$s1       ", "$s2       ", "$s3       ", "$s4       ", "$s5       ", "$s6       ", "$s7       ",
            "$t8       ", "$t9       ", "$k0       ", "$k1       ", "$s8       ", "$status   ", "$badvaddr ", "$cause    ",
            "$pc       ", "$sp       ", "$hi       ", "$lo       ", "$fir      ", "$fcsr     ", "$ra       ", "$gp       ", ]

@memoize
def mips_nop_insn():
    # https://en.wikipedia.org/wiki/MIPS_instruction_set
    # sll $0,$0,0
    return b"\x00\x00\x00\x00"

@memoize
def mips_return_register():
    return "$v0"

@memoize
def mips_flag_register():
    return "$fcsr"

def mips_flags_to_human(val=None):
    # mips architecture does not use processor status word (flag register)
    return ""

def mips_is_cbranch(insn):
    mnemo = ["bl", ]
    return any( filter(lambda x: x == insn, mnemo) )

def mips_is_cbranch(insn):
    mnemo = ["beq", "bne", "beqz", "bnez", "bgtz", "bgez", "bltz", "blez", ]
    return any( filter(lambda x: x == insn, mnemo) )

def mips_is_branch_taken(mnemo, operands):
    if mnemo=="beq": return get_register_ex(operands[0]) == get_register_ex(operands[1]), ""
    if mnemo=="bne": return get_register_ex(operands[0]) != get_register_ex(operands[1]), ""
    if mnemo=="beqz": return get_register_ex(operands[0]) == 0, ""
    if mnemo=="bnez": return get_register_ex(operands[0]) != 0, ""
    if mnemo=="bgtz": return get_register_ex(operands[0]) > 0, ""
    if mnemo=="bgez": return get_register_ex(operands[0]) >= 0, ""
    if mnemo=="bltz": return get_register_ex(operands[0]) < 0, ""
    if mnemo=="blez": return get_register_ex(operands[0]) <= 0, ""
    return False, ""

@memoize
def mips_function_parameters():
    return ['$a0','$a1','$a2','$a3']


######################[ AARCH64 specific ]######################

@memoize
def aarch64_registers():
    return ["$x0       ", "$x1       ", "$x2       ", "$x3       ", "$x4       ", "$x5       ", "$x6       ", "$x7       ",
            "$x8       ", "$x9       ", "$x10      ", "$x11      ", "$x12      ", "$x13      ", "$x14      ", "$x15      ",
            "$x16      ", "$x17      ", "$x18      ", "$x19      ", "$x20      ", "$x21      ", "$x22      ", "$x23      ",
            "$x24      ", "$x25      ", "$x26      ", "$x27      ", "$x28      ", "$x29      ", "$x30      ", "$sp       ",
            "$pc       ", "$cpsr     ", "$fpsr     ", "$fpcr     ", ]

@memoize
def aarch64_return_register():
    return "$x0"

@memoize
def aarch64_flag_register():
    return "$cpsr"

@memoize
def aarch64_flags_table():
    table = { 31: "negative",
              30: "zero",
              29: "carry",
              28: "overflow",
              7: "interrupt",
              6: "fast"
    }
    return table

def aarch64_flags_to_human(val=None):
    # http://events.linuxfoundation.org/sites/events/files/slides/KoreaLinuxForum-2014.pdf
    reg = aarch64_flag_register()
    if not val:
        val = get_register_ex( reg )
    return flags_to_human(val, aarch64_flags_table())

def aarch64_is_cbranch(insn):
    return arm_is_cbranch(insn)

def aarch64_is_cbranch(insn):
    return arm_is_cbranch(insn)

def aarch64_is_branch_taken(insn):
    return arm_is_branch_taken(insn)

@memoize
def aarch64_function_parameters():
    return ['$x0','$x1','$x2','$x3']


################################################################

@memoize
def all_registers():
    if is_arm():         return arm_registers()
    elif is_aarch64():   return aarch64_registers()
    elif is_x86_32():    return x86_32_registers()
    elif is_x86_64():    return x86_64_registers()
    elif is_powerpc():   return powerpc_registers()
    elif is_ppc64():     return powerpc_registers()
    elif is_sparc():     return sparc_registers()
    elif is_sparc64():   return sparc_registers()
    elif is_mips():      return mips_registers()
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


@memoize
def nop_insn():
    if is_arm():         return arm_nop_insn()
    elif is_aarch64():   return arm_nop_insn()
    elif is_x86_32():    return x86_32_nop_insn()
    elif is_x86_64():    return x86_32_nop_insn()
    elif is_powerpc():   return powerpc_nop_insn()
    elif is_ppc64():     return powerpc_nop_insn()
    elif is_sparc():     return sparc_nop_insn()
    elif is_sparc64():   return sparc_nop_insn()
    elif is_mips():      return mips_nop_insn()
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


@memoize
def return_register():
    if is_arm():         return arm_return_register()
    elif is_aarch64():   return aarch64_return_register()
    elif is_x86_32():    return x86_32_return_register()
    elif is_x86_64():    return x86_64_return_register()
    elif is_powerpc():   return powerpc_return_register()
    elif is_ppc64():     return powerpc_return_register()
    elif is_sparc():     return sparc_return_register()
    elif is_sparc64():   return sparc_return_register()
    elif is_mips():      return mips_return_register()
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


@memoize
def flag_register():
    if is_arm():         return arm_flag_register()
    elif is_aarch64():   return aarch64_flag_register()
    elif is_x86_32():    return x86_flag_register()
    elif is_x86_64():    return x86_flag_register()
    elif is_powerpc():   return powerpc_flag_register()
    elif is_ppc64():     return powerpc_flag_register()
    elif is_mips():      return mips_flag_register()
    elif is_sparc():     return sparc_flag_register()
    elif is_sparc64():   return sparc_flag_register()
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


@memoize
def flags_table():
    if is_x86_32():       return x86_flags_table()
    elif is_x86_64():     return x86_flags_table()
    elif is_arm():        return arm_flags_table()
    elif is_aarch64():    return aarch64_flags_table()
    elif is_powerpc():    return powerpc_flags_table()
    elif is_ppc64():      return powerpc_flags_table()
    elif is_sparc():      return sparc_flags_table()
    elif is_sparc64():    return sparc_flags_table()
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


def flag_register_to_human(val=None):
    if is_arm():         return arm_flags_to_human(val)
    elif is_aarch64():   return aarch64_flags_to_human(val)
    elif is_x86_32():    return x86_flags_to_human(val)
    elif is_x86_64():    return x86_flags_to_human(val)
    elif is_powerpc():   return powerpc_flags_to_human(val)
    elif is_ppc64():     return powerpc_flags_to_human(val)
    elif is_mips():      return mips_flags_to_human(val)
    elif is_sparc():     return sparc_flags_to_human(val)
    elif is_sparc64():   return sparc_flags_to_human(val)
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())

def is_call_instruction(insn):
    (address, location, mnemo, operands) = gef_parse_gdb_instruction(insn)
    if   is_arm():       return arm_is_call(mnemo)
    elif is_aarch64():   return aarch64_is_call(mnemo)
    elif is_x86_32():    return x86_is_call(mnemo)
    elif is_x86_64():    return x86_is_call(mnemo)
    elif is_powerpc():   return powerpc_is_call(mnemo)
    elif is_ppc64():     return powerpc_is_call(mnemo)
    elif is_mips():      return mips_is_call(mnemo)
    elif is_sparc():     return sparc_is_call(mnemo)
    elif is_sparc64():   return sparc_is_call(mnemo)
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())

def is_conditional_branch(insn):
    (address, location, mnemo, operands) = gef_parse_gdb_instruction(insn)
    if   is_arm():       return arm_is_cbranch(mnemo)
    elif is_aarch64():   return aarch64_is_cbranch(mnemo)
    elif is_x86_32():    return x86_is_cbranch(mnemo)
    elif is_x86_64():    return x86_is_cbranch(mnemo)
    elif is_powerpc():   return powerpc_is_cbranch(mnemo)
    elif is_ppc64():     return powerpc_is_cbranch(mnemo)
    elif is_mips():      return mips_is_cbranch(mnemo)
    elif is_sparc():     return sparc_is_cbranch(mnemo)
    elif is_sparc64():   return sparc_is_cbranch(mnemo)
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())

def is_branch_taken(insn):
    (address, location, mnemo, operands) = gef_parse_gdb_instruction(insn)
    if   is_arm():       return arm_is_branch_taken(mnemo)
    elif is_aarch64():   return aarch64_is_branch_taken(mnemo)
    elif is_x86_32():    return x86_is_branch_taken(mnemo)
    elif is_x86_64():    return x86_is_branch_taken(mnemo)
    elif is_powerpc():   return powerpc_is_branch_taken(mnemo)
    elif is_ppc64():     return powerpc_is_branch_taken(mnemo)
    elif is_mips():      return mips_is_branch_taken(mnemo, operands)
    elif is_sparc():     return sparc_is_branch_taken(mnemo)
    elif is_sparc64():   return sparc_is_branch_taken(mnemo)
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())

@memoize
def function_parameters():
    if   is_arm():       return arm_function_parameters()
    elif is_aarch64():   return aarch64_function_parameters()
    elif is_x86_32():    return x86_32_function_parameters()[0]
    elif is_x86_64():    return x86_64_function_parameters()
    elif is_powerpc():   return powerpc_function_parameters()
    elif is_ppc64():     return powerpc_function_parameters()
    elif is_mips():      return mips_function_parameters()
    elif is_sparc():     return sparc_function_parameters()
    elif is_sparc64():   return sparc_function_parameters()
    raise GefUnsupportedOS("OS type is currently not supported: %s" % get_arch())


def write_memory(address, buffer, length=0x10):
    if PYTHON_MAJOR == 2: buffer = str(buffer)
    return gdb.selected_inferior().write_memory(address, buffer, length)


def read_memory(addr, length=0x10):
    if PYTHON_MAJOR == 2:
        return gdb.selected_inferior().read_memory(addr, length)

    return gdb.selected_inferior().read_memory(addr, length).tobytes()


def read_int_from_memory(addr):
    arch = get_memory_alignment(to_byte=True)
    mem = read_memory(addr, arch)
    fmt = endian_str()+"I" if arch==4 else endian_str()+"Q"
    return struct.unpack(fmt, mem)[0]


def read_cstring_from_memory(address):
    """
    Read a C-string from memory using GDB memory access.
    """
    char_ptr = gdb.lookup_type("char").pointer()
    res = gdb.Value(address).cast(char_ptr).string().strip()

    i = res.find('\n')
    if i!=-1 and len(res) > get_memory_alignment(to_byte=True):
        res = res[:i] + "[...]"

    return res


def is_readable_string(address):
    """
    Here we will assume that a readable string is
    a consecutive byte array whose
    * last element is 0x00 (i.e. it is a C-string)
    * and each byte is printable
    """
    try:
        cstr = read_cstring_from_memory(address)
        return type(cstr) == unicode and len(cstr) > 0 and all([x in string.printable for x in cstr])
    except UnicodeDecodeError as e:
        return False


def is_alive():
    """Check if GDB is running."""
    try:
        pid = get_pid()
        return pid > 0
    except gdb.error as e:
        return False
    return False


def if_gdb_running(f):
    """Decorator wrapper to check if GDB is running."""
    @functools.wraps(f)
    def wrapper(*args, **kwds):
        if is_alive():
            return f(*args, **kwds)
        else:
            warn("No debugging session active")
    return wrapper


def get_register(regname):
    """
    Get register value. Exception will be raised if expression cannot be parse.
    This function won't catch on purpose.
    @param regname: expected register
    @return register value
    """
    t = gdb.lookup_type("unsigned long")
    reg = gdb.parse_and_eval(regname)
    return long( reg.cast(t) )

def get_register_ex(regname):
    t = gdb.execute("info register %s" % regname, to_string=True)
    for v in t.split(" "):
        v = v.strip()
        if v.startswith("0x"):
            return long(v.strip().split("\t",1)[0], 16)
    return 0

def get_pc():
    try:
        return get_register("$pc")
    except:
        return get_register_ex("$pc")

def get_sp():
    try:
        return get_register("$sp")
    except:
        return get_register_ex("$sp")


def get_pid():
    return get_frame().pid


def get_filepath():
    filename = gdb.current_progspace().filename

    if is_remote_debug():

        # if no filename specified, try downloading target from /proc
        if filename == None:
            pid = get_pid()

            if pid > 0:
                return download_file("/proc/%d/exe" % pid, use_cache=True)
            else:
                return None

        # if target is remote file, download
        elif filename.startswith("target:"):
            return download_file(filename[len("target:"):], use_cache=True)
        else:
            return filename
    else:
        return filename


def download_file(target, use_cache=False):
    """Download filename `target` inside the mirror tree in /tmp"""
    try:
        local_root = '{0:s}/gef'.format(tempfile.gettempdir())
        local_path = local_root + '/' + os.path.dirname( target )
        local_name = local_path + '/' + os.path.basename( target )
        if use_cache and os.path.isfile(local_name):
            return local_name
        gef_makedirs(local_path)
        gdb.execute("remote get {0:s} {1:s}".format(target, local_name))
    except Exception as e:
        err(str(e))
        local_name = None
    return local_name


def open_file(path, use_cache=False):
    """Attempt to open the given file, if remote debugging is active, download
    it first to the mirror in /tmp/"""
    if is_remote_debug():
        lpath = download_file(path, use_cache)
        if not lpath:
            raise IOError("cannot open remote path %s" % path)
        return open(lpath)
    else:
        return open(path)


def get_filename():
    return os.path.basename(get_filepath())


def get_function_length(sym):
    """Attempt to get the length of the raw bytes of a function."""
    dis = gdb.execute("disassemble %s"%sym, to_string=True).splitlines()
    start_addr = int(dis[1].split()[0], 16)
    end_addr = int(dis[-2].split()[0], 16)
    return end_addr - start_addr


@memoize
def get_process_maps():
    sections = []

    try:
        pid = get_pid()
        proc = "/proc/%d/maps" % pid

        f = open_file(proc, use_cache=False)
        while True:
            line = f.readline()
            if len(line) == 0:
                break

            line = line.strip()
            addr, perm, off, dev, rest = line.split(" ", 4)
            rest = rest.split(" ", 1)
            if len(rest) == 1:
                inode = rest[0]
                pathname = ""
            else:
                inode = rest[0]
                pathname = rest[1].replace(' ', '')

            addr_start, addr_end = addr.split("-")
            addr_start, addr_end = long(addr_start, 16), long(addr_end, 16)
            off = long(off, 16)

            perm = Permission.from_process_maps(perm)

            section = Section(page_start  = addr_start,
                              page_end    = addr_end,
                              offset      = off,
                              permission  = perm,
                              inode       = inode,
                              path        = pathname)

            sections.append( section )

    except Exception as e:
        if is_debug():
            warn("Failed to read /proc/<PID>/maps, using GDB sections info")
        sections = get_info_sections()

    return sections


@memoize
def get_info_sections():
    sections = []
    stream = StringIO(gdb.execute("maintenance info sections", to_string=True))

    while True:
        line = stream.readline()
        if len(line) == 0:
            break

        try:
            parts = [x.strip() for x in line.split()]
            index = parts[0][1:-1]
            addr_start, addr_end = [ long(x, 16) for x in parts[1].split("->") ]
            at = parts[2]
            off = long(parts[3][:-1], 16)
            path = parts[4]
            inode = ""
            perm = Permission.from_info_sections(parts[5:])

            section = Section(page_start  = addr_start,
                              page_end    = addr_end,
                              offset      = off,
                              permission  = perm,
                              inode       = inode,
                              path        = path)

            sections.append( section )

        except IndexError:
            continue
        except ValueError:
            continue

    return sections


def get_info_files():
    global __infos_files__

    cmd = gdb.execute("info files", to_string=True)
    lines = cmd.split("\n")

    if len(lines) < len(__infos_files__):
        return __infos_files__

    for line in lines:
        line = line.strip().rstrip()

        if len(line) == 0:
            break

        if not line.startswith("0x"):
            continue

        blobs = [x.strip() for x in line.split(' ')]
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

        __infos_files__.append( info )

    return __infos_files__


def process_lookup_address(address):
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


def process_lookup_path(name, perm=Permission.READ|Permission.WRITE|Permission.EXECUTE):
    if not is_alive():
        err("Process is not running")
        return None

    for sect in get_process_maps():
        if name in sect.path and sect.permission.value & perm:
            return sect

    return None


def file_lookup_address(address):
    for info in get_info_files():
        if info.zone_start <= address < info.zone_end:
            return info
    return None


def lookup_address(address):
    addr = Address(value=address)
    sect = process_lookup_address(address)
    info = file_lookup_address(address)
    if sect is None and info is None:
        # i.e. there is no info on this address
        return None

    if sect:
        addr.section = sect

    if info:
        addr.info = info

    return addr


def XOR(data, key):
    key = binascii.unhexlify(key)
    if PYTHON_MAJOR == 2:
        return b''.join([chr(ord(x) ^ ord(y)) for (x,y) in zip(data, itertools.cycle(key))])

    return bytearray([x ^ y for (x,y) in zip(data, itertools.cycle(key))])


def ishex(pattern):
    if pattern.startswith("0x") or pattern.startswith("0X"):
        pattern = pattern[2:]
    return all(c in string.hexdigits for c in pattern)


def hook_stop_handler(event):
    gdb.execute("context")
    return


def new_objfile_handler(event):
    reset_all_caches()
    return


def exit_handler(event):
    reset_all_caches()
    return


def get_terminal_size():
    """
    Portable function to retrieve the current terminal size.
    """
    cmd = struct.unpack('hh',  fcntl.ioctl(1, termios.TIOCGWINSZ, '1234'))
    tty_rows, tty_columns = int(cmd[0]), int(cmd[1])
    return tty_rows, tty_columns


def get_generic_arch(module, prefix, arch, mode, big_endian, to_string=False):
    """
    Retrieves architecture and mode from the arguments for use for the holy
    {cap,key}stone/unicorn trinity.
    """
    if to_string:
        arch = "%s.%s_ARCH_%s" % (module.__name__, prefix, arch)
        if mode:
            mode = "%s.%s_MODE_%s" % (module.__name__, prefix, str(mode))
        else:
            mode = ""
        if is_big_endian():
            mode += " + %s.%s_MODE_BIG_ENDIAN" % (module.__name__, prefix)
        else:
            mode += " + %s.%s_MODE_LITTLE_ENDIAN" % (module.__name__, prefix)

    else:
        arch = getattr(module, "%s_ARCH_%s" % (prefix, arch))
        if mode:
            mode = getattr(module, "%s_MODE_%s" % (prefix, mode))
        else:
            mode = 0
        if big_endian:
            mode += getattr(module, "%s_MODE_BIG_ENDIAN" % prefix)
        else:
            mode += getattr(module, "%s_MODE_LITTLE_ENDIAN" % prefix)

    return arch, mode


def get_generic_running_arch(module, prefix, to_string=False):
    """
    Retrieves architecture and mode from the current context.
    """

    if not is_alive():
        return None, None

    if   is_x86_32():    arch, mode = "X86", "32"
    elif is_x86_64():    arch, mode = "X86", "64"
    elif is_powerpc():   arch, mode = "PPC", "PPC32"
    elif is_ppc64():     arch, mode = "PPC", "PPC64"
    elif is_mips():      arch, mode = "MIPS", "MIPS32"
    elif is_sparc():     arch, mode = "SPARC", None
    elif is_sparc64():   arch, mode = "SPARC", "V9"
    elif is_arm():       arch, mode = "ARM", "ARM"
    elif is_aarch64():   arch, mode = "ARM", "ARM"
    else:
        raise GefUnsupportedOS("Emulation not supported for your OS")

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
            raise GefUnsupportedOS("Capstone not supported for PPC64 yet.")

        arch = "PPC"
        mode = "32"
        endian = is_big_endian()
        return get_generic_arch(capstone, "CS", arch, mode, endian, to_string)

    if (arch, mode, endian) == (None,None,None):
        return get_generic_running_arch(capstone, "CS", to_string)
    return get_generic_arch(capstone, "CS", arch, mode, endian, to_string)

def get_keystone_arch(arch=None, mode=None, endian=None, to_string=False):
    keystone = sys.modules["keystone"]
    if (arch, mode, endian) == (None,None,None):
        return get_generic_running_arch(keystone, "KS", to_string)
    return get_generic_arch(keystone, "KS", arch, mode, endian, to_string)

def get_unicorn_registers(to_string=False):
    "Returns a dict matching the Unicorn identifier for a specific register."
    unicorn = sys.modules['unicorn']
    regs = {}

    if is_x86_32() or is_x86_64():   arch = "x86"
    elif is_powerpc():               arch = "ppc"
    elif is_ppc64():                 arch = "ppc"
    elif is_mips():                  arch = "mips"
    elif is_sparc():                 arch = "sparc"
    elif is_sparc64():               arch = "sparc"
    elif is_arm():                   arch = "arm"
    elif is_aarch64():               arch = "arm64"
    else:
        raise GefUnsupportedOS("Oops")

    const = getattr(unicorn, arch + "_const")
    for r in all_registers():
        regname = "UC_%s_REG_%s" % (arch.upper(), r.strip()[1:].upper())
        if to_string:
            regs[r] = "%s.%s" % (const.__name__, regname)
        else:
            regs[r] = getattr(const, regname)
    return regs


def keystone_assemble(code, arch, mode, *args, **kwargs):
    """Assembly encoding function based on keystone."""
    keystone = sys.modules["keystone"]
    if PYTHON_MAJOR==3: code = bytes(code, encoding="utf-8")
    addr = kwargs.get("addr", 0x1000)

    try:
        ks = keystone.Ks(arch, mode)
        enc, cnt = ks.asm(code, addr)
    except keystone.KsError as e:
        err("Keystone assembler error: {:s}".format(e))
        return None

    enc = bytearray(enc)
    if kwargs.get("raw", False) != True:
        # print as string
        s = binascii.hexlify(enc)
        enc = b"\\x" + b"\\x".join( [s[i:i+2] for i in range(0, len(s), 2)] )
        enc = enc.decode("utf-8")

    return enc


@memoize
def get_elf_headers(filename=None):
    if filename is None:
        filename = get_filepath()

    if filename.startswith("target:"):
        warn("Your file is remote, you should try using `gef-remote` instead")
        return

    return Elf(filename)


@memoize
def is_elf64(filename=None):
    elf = get_elf_headers(filename)
    return elf.e_class == 0x02

@memoize
def is_elf32(filename=None):
    elf = get_elf_headers(filename)
    return elf.e_class == 0x01

@memoize
def is_x86_64(filename=None):
    elf = get_elf_headers(filename)
    return elf.e_machine==0x3e

@memoize
def is_x86_32(filename=None):
    elf = get_elf_headers(filename)
    return elf.e_machine==0x03

@memoize
def is_arm(filename=None):
    elf = get_elf_headers(filename)
    return elf.e_machine==0x28

@memoize
def is_arm_thumb():
    # http://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
    return is_arm() and get_register("$cpsr") & (1<<5)

@memoize
def is_mips():
    elf = get_elf_headers()
    return elf.e_machine==0x08

@memoize
def is_powerpc():
    elf = get_elf_headers()
    return elf.e_machine==0x14 # http://refspecs.freestandards.org/elf/elfspec_ppc.pdf

def is_ppc64():
    elf = get_elf_headers()
    return elf.e_machine==0x15 # http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html

@memoize
def is_sparc():
    elf = get_elf_headers()
    return elf.e_machine==0x02

@memoize
def is_sparc64():
    elf = get_elf_headers()
    return elf.e_machine==0x12

@memoize
def is_aarch64():
    elf = get_elf_headers()
    return elf.e_machine==0xb7

def get_memory_alignment(to_byte=False):
    if is_elf32():
        return 32 if not to_byte else 4
    elif is_elf64():
        return 64 if not to_byte else 8

    raise GefUnsupportedMode("GEF is running under an unsupported mode")

def clear_screen():
    gdb.execute("shell clear")
    return

def format_address(addr):
    memalign_size = get_memory_alignment()
    if memalign_size == 32:
        print
        return "%#.8x" % (addr & 0xFFFFFFFF)
    elif memalign_size == 64:
        return "%#.16x" % (addr & 0xFFFFFFFFFFFFFFFF)

def align_address(address):
    if get_memory_alignment()==32:
        ret = address & 0x00000000FFFFFFFF
    else:
        ret = address & 0xFFFFFFFFFFFFFFFF
    return ret

def align_address_to_page(address):
    a = align_address(address) >> DEFAULT_PAGE_ALIGN_SHIFT
    return a << DEFAULT_PAGE_ALIGN_SHIFT

def parse_address(address):
    if ishex(address):
        return long(address, 16)

    t = gdb.lookup_type("unsigned long")
    a = gdb.parse_and_eval( address ).cast(t)
    return long(a)

def is_in_x86_kernel(address):
    address = align_address(address)
    memalign = get_memory_alignment()-1
    return (address >> memalign) == 0xF

@memoize
def endian_str():
    elf = get_elf_headers()
    if elf.e_endianness == 0x01:
        return "<" # LE
    return ">" # BE


@memoize
def is_remote_debug():
    return "remote" in gdb.execute("maintenance print target-stack", to_string=True)


def de_bruijn(alphabet, n):
    """
    De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib)
    Source: https://github.com/Gallopsled/pwntools/blob/master/pwnlib/util/cyclic.py#L38
    """
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
    """
    Create a cyclic pattern based on de Bruijn sequence.
    """
    charset = b"""abcdefghijklmnopqrstuvwxyz"""
    cycle = get_memory_alignment(to_byte=True) if is_alive() else 4
    i = 0
    res = []

    for c in de_bruijn(charset, cycle):
        if i == length: break
        res.append(c)
        i += 1

    return bytearray(res)


def dereference(addr):
    """
    gef-wrapper for gdb dereference fonction.
    """
    try:
        unsigned_long_type = gdb.lookup_type('unsigned long').pointer()
        ret = gdb.Value(addr).cast(unsigned_long_type).dereference()
    except gdb.MemoryError:
        if is_debug():
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
            traceback.print_exception(exc_type, exc_value, exc_traceback,limit=5, file=sys.stdout)

        ret = None
    return ret


def gef_convenience(value):
    global __gef_convenience_vars_index__
    var_name = "$_gef%d" % __gef_convenience_vars_index__
    __gef_convenience_vars_index__ += 1
    gdb.execute("""set %s = %s """ % (var_name, value))
    return var_name


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
        if is_arm():
            regs = arm_function_parameters()
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_aarch64():
            regs = aarch64_function_parameters()
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_x86_64():
            regs = x86_32_function_parameters()
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_sparc():
            regs = powerpc_function_parameters()
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_mips():
            regs = mips_function_parameters()
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_powerpc():
            regs = powerpc_function_parameters()
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_x86_32():
            sp = get_sp()
            m = get_memory_alignment(to_byte=True)
            val = sp + (self.num_args * m) + m
            ptr = read_int_from_memory( val )
            addr = lookup_address( ptr )
            ptr = hex(ptr)

        if addr is None:
            return False

        if addr.section.permission.value & Permission.WRITE:
            content = read_cstring_from_memory(addr.value)

            print(titlify("Format String Detection"))
            info("Possible insecure format string '%s' %s %#x: '%s'" % (ptr, right_arrow, addr.value, content))
            info("Triggered by '%s()'" % self.location)

            name = addr.info.name if addr.info else addr.section.path
            m = "Reason:\n"
            m+= "Call to '%s()' with format string argument in position #%d is in " % (self.location, self.num_args)
            m+= "page %#x (%s) that has write permission" % (addr.section.page_start, name)
            warn(m)

            return True

        return False


class PatchBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.)"""

    def __init__(self, func, retval):
        super(PatchBreakpoint, self).__init__(func, gdb.BP_BREAKPOINT, internal=False)
        self.func = func
        self.retval = retval

        m = "All calls to '%s' will be skipped" % self.func
        if self.retval is not None:
            m+= " (with return value as %#x)" % self.retval
        info(m)
        return

    def stop(self):
        retaddr = gdb.selected_frame().older().pc()
        retreg  = return_register()

        if self.retval is not None:
            cmd = "set %s = %#x" % (retreg, self.retval)
            gdb.execute( cmd )

        cmd = "set $pc = %#x" % (retaddr)
        gdb.execute( cmd )

        m = "Ignoring call to '%s'" % self.func
        if self.retval is not None:
            m+= "(setting %s to %#x)" % (retreg, self.retval)

        ok(m)
        return False  # never stop at this breakpoint


class SetRegisterBreakpoint(gdb.Breakpoint):
    """When hit, this temporary breakpoint simply sets one specific register to a given value."""

    def __init__(self, func, reg, retval, force_stop=False):
        super(SetRegisterBreakpoint, self).__init__(func, gdb.BP_BREAKPOINT, internal=False)
        self.func = func
        self.reg = reg
        self.retval = retval
        self.force_stop = force_stop
        return

    def stop(self):
        gdb.execute("set %s = %d" % (self.reg, self.retval))
        ok("Setting Return Value register (%s) to %d" % (self.reg, self.retval))
        self.delete()
        return self.force_stop


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
        gdb.execute("set $pc = %#x" % self.original_pc)
        return True


#
# Commands
#

class GenericCommand(gdb.Command):
    """Generic class for invoking commands"""

    def __init__(self, *args, **kwargs):
        self.pre_load()

        required_attrs = ["do_invoke", "_cmdline_", "_syntax_"]

        for attr in required_attrs:
            if not hasattr(self, attr):
                raise NotImplemented("Invalid class: missing '%s'" % attr)

        self.__doc__  += "\n" + "Syntax: " + self._syntax_

        command_type = kwargs.setdefault("command", gdb.COMMAND_OBSCURE)
        complete_type = kwargs.setdefault("complete", gdb.COMPLETE_NONE)
        prefix = kwargs.setdefault("prefix", True)
        super(GenericCommand, self).__init__(self._cmdline_, command_type, complete_type, prefix)
        self.post_load()
        return


    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        self.do_invoke(argv)
        return


    def usage(self):
        err("Syntax\n" + self._syntax_ )
        return


    def pre_load(self):
        return


    def post_load(self):
        return


    def add_setting(self, name, value):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        __config__[ key ] = (value, type(value))
        return


    def get_setting(self, name):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        return __config__[ key ][0]


    def has_setting(self, name):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        return key in list( __config__.keys() )


    def del_setting(self, name):
        key = "%s.%s" % (self.__class__._cmdline_, name)
        del ( __config__[ key ] )
        return


# Copy/paste this template for new command
# class TemplateCommand(GenericCommand):
# """TemplaceCommand: description here will be seen in the help menu for the command."""

    # _cmdline_ = "template-fake"
    # _syntax_  = "%s" % _cmdline_
    # _aliases_ = ["tpl-fk", ]

    # def __init__(self):
    # super(TemplateCommand, self).__init__(complete=gdb.COMPLETE_FILENAME)
    # return
    # def pre_load(self):
    # return
    # def post_load(self):
    # return
    # def do_invoke(self, argv):
    # return

class PCustomCommand(GenericCommand):
    """Dump user defined structure.
    This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows
    to apply structures (from symbols or custom) directly to an address.
    Custom structures can be defined in pure Python using ctypes, and should be stored
    in a specific directory, whose path must be stored in the `pcustom.struct_path`
    configuration setting."""

    _cmdline_ = "pcustom"
    _syntax_  = "%s [-l] [StructA [0xADDRESS] [-e]]" % _cmdline_
    _aliases_ = ["dt", ]

    def __init__(self):
        super(PCustomCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL, prefix=False)
        self.add_setting("struct_path", tempfile.gettempdir()+'/gef/structs')
        self.template_body = b"""from ctypes import *

class Template(Structure):
    _fields_ = []

"""
        return

    def do_invoke(self, argv):
        argc = len(argv)
        if argc==0:
            self.usage()
            return

        if argv[0]=="-l":
            self.list_custom_structures()
            return

        structure_name = argv[0]
        if argc==1:
            self.dump_structure(structure_name)
            return

        if argv[1]=="-e":
            self.create_or_edit_structure(structure_name)
            return

        if not is_alive():
            return

        try:
            address = long(gdb.parse_and_eval(argv[1]))
        except gdb.error:
            err("Failed to parse '%s'" % argv[1])
            return

        self.apply_structure_to_address(structure_name, address)
        return

    def get_custom_structure_filepath(self, struct):
        return self.get_setting("struct_path") + "/" + struct + ".py"

    def is_valid_custom_structure(self, struct):
        return os.access(self.get_custom_structure_filepath(struct), os.R_OK)

    def get_custom_structure_size(self, struct):
        return sum([ctypes.sizeof(x[1]) for x in struct._fields_])

    def dump_structure(self, struct_name):
        try:
            gdb.execute("ptype struct %s" % struct_name)
            return
        except gdb.error as e:
            pass

        if not self.dump_custom_structure(struct_name):
            err("Invalid structure name '%s'" % struct_name)
        return

    def dump_custom_structure(self, struct_name):
        if not self.is_valid_custom_structure(struct_name):
            return False

        fullname = self.get_custom_structure_filepath(struct_name)
        defined_struct = imp.load_source("template", fullname)
        template = defined_struct.Template()
        _offset = 0
        for (_name, _type) in template._fields_:
            _size = ctypes.sizeof(_type)
            print("+%04x %s %s (%#x)" % (_offset, _name, _type.__name__, _size))
            _offset += _size
        return True

    def deserialize(self, struct, data):
        length = min(len(data), ctypes.sizeof(struct))
        ctypes.memmove(ctypes.addressof(struct), data, length)
        return

    def apply_structure_to_address(self, struct_name, addr):
        if not self.is_valid_custom_structure(struct_name):
            err("Invalid structure name '%s'" % struct_name)
            return

        fullname = self.get_custom_structure_filepath(struct_name)
        defined_struct = imp.load_source("template", fullname)
        template = defined_struct.Template()

        try:
            data = read_memory(addr, self.get_custom_structure_size(template))
        except gdb.MemoryError:
            err("Cannot reach memory %#x" % addr)
            return

        self.deserialize(template, data)
        _offset = 0
        _regsize = get_memory_alignment(to_byte=True)

        for field in template._fields_:
            _name, _type = field
            _size = ctypes.sizeof(_type)
            _value = getattr(template, _name)

            if    (_regsize==4 and _type is ctypes.c_uint32) \
               or (_regsize==8 and _type is ctypes.c_uint64) \
               or (_regsize==ctypes.sizeof(ctypes.c_void_p) and _type is ctypes.c_void_p):
                # try to parse pointers
                _value = right_arrow.join( DereferenceCommand.dereference_from(_value) )

            line = ("%#x+0x%04x %s : " % (addr, _offset, _name)).ljust(40)
            line+= "%s (%s)" % (_value, _type.__name__)
            parsed_value = self.get_ctypes_value(template, _name, _value)
            if len(parsed_value):
                line+= " %s %s" % (right_arrow, parsed_value)
            print(line)
            _offset += _size
        return


    def get_ctypes_value(self, struct, item, value):
        if not hasattr(struct, "_values_"): return ""
        values_list = getattr(struct, "_values_")
        default = ""
        for name, values in values_list:
            if name != item: continue
            for val, desc in values:
                if value==val: return desc
                if val==None: default = desc
        return default


    def create_or_edit_structure(self, structure_name):
        path = self.get_setting("struct_path")
        fullname = self.get_custom_structure_filepath(structure_name)
        if not os.path.isdir(path):
            info("Creating path '%s'" % path)
            gef_makedirs(path)
        elif not self.is_valid_custom_structure(structure_name):
            info("Creating '%s' from template"%fullname)
            with open(fullname, "wb") as f:
                f.write(self.template_body)
        else:
            info("Editing '%s'" % fullname)

        cmd = os.getenv("EDITOR").split() if os.getenv("EDITOR") else ["nano",]
        cmd.append(fullname)
        retcode = subprocess.call(cmd)
        return retcode

    def list_custom_structures(self):
        info("Listing custom structures:")
        for filen in os.listdir(self.get_setting("struct_path")):
            if not filen.endswith("py"): continue
            print("%s %s" % (right_arrow, filen.replace(".py", "")))
        return


class RetDecCommand(GenericCommand):
    """Decompile code from GDB context using RetDec API."""

    _cmdline_ = "retdec"
    _syntax_  = "%s [-r RANGE1-RANGE2][-s SYMBOL][-a][-h]" % _cmdline_
    _aliases_ = ["decompile", ]

    def __init__(self):
        super(RetDecCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL, prefix=False)
        self.add_setting("key", "1dd7cb8f-ca9f-4663-811b-2095b87d7faa")
        self.add_setting("path", tempfile.gettempdir())
        self.decompiler = None
        return

    def pre_load(self):
        try:
            import retdec
            import retdec.decompiler
        except ImportError as ioe:
            msg = "Missing Python `retdec-python` package. "
            raise GefMissingDependencyException( msg )
        return

    @if_gdb_running
    def do_invoke(self, argv):
        if   is_x86_32():   arch = "x86"
        elif is_arm():      arch = "arm"
        elif is_mips():     arch = "mips"
        elif is_powerpc():  arch = "powerpc"
        else:
            err("RetDec does not decompile '%s'" % get_arch())
            return

        if self.decompiler is None:
            retdec = sys.modules["retdec"]
            retdec_decompiler = sys.modules["retdec.decompiler"]
            self.decompiler = retdec.decompiler.Decompiler(api_key=self.get_setting("key"))

        params = {
            "architecture": arch,
            "target_language": "c",
            "raw_endian": "big" if is_big_endian() else "little",
            "decomp_var_names": "readable",
            "decomp_emit_addresses": "no",
            "generate_cg": "no",
            "generate_cfg": "no",
            "comp_compiler": "gcc",
        }

        opts, args = getopt.getopt(argv, "r:s:ah")
        for o, a in opts:
            if   o == "-r":
                range_from, range_to = map(lambda x: int(x,16), a.split("-", 1))
                fd, filename = tempfile.mkstemp()
                with os.fdopen(fd, "wb") as f:
                    length = range_to - range_from
                    f.write(read_memory(range_from, length))
                params["mode"] = "raw"
                params["file_format"] = "elf"
                params["raw_section_vma"] = hex(range_from)
                params["raw_entry_point"] = hex(range_from)
            elif o == "-s":
                try:
                    value = gdb.parse_and_eval(a)
                except gdb.error:
                    err("No symbol named '%s'" % a)
                    return
                range_from = long(value.address)
                fd, filename = tempfile.mkstemp()
                with os.fdopen(fd, "wb") as f:
                    f.write(read_memory(range_from, get_function_length(a)))
                params["mode"] = "raw"
                params["file_format"] = "elf"
                params["raw_section_vma"] = hex(range_from)
                params["raw_entry_point"] = hex(range_from)
            elif o == "-a":
                filename = get_filepath()
                params["mode"] = "bin"
            else:
                self.usage()
                return

        params["input_file"] = filename
        if self.send_to_retdec(params)==False:
            return

        fname = self.get_setting("path") + '/' + os.path.basename(filename) + '.c'
        with open(fname, 'r') as f:
            p = re.compile(r'unknown_([a-f0-9]+)')
            for l in f.readlines():
                l = l.rstrip()
                if len(l.strip())==0 or l.strip().startswith("//"):
                    continue
                # try to fix the unknown with the current context
                for match in p.finditer(l):
                    s = match.group(1)
                    addr = int(s, 16)
                    dis = gdb.execute("x/1i %#x" % addr, to_string=True)
                    addr, loc, mnemo, ops = gef_parse_gdb_instruction(dis.strip())
                    if len(loc):
                        l = l.replace("unknown_%s"%s, loc)
                print(l)
        return


    def send_to_retdec(self, params):
        retdec = sys.modules["retdec"]

        try:
            path = self.get_setting("path")
            decompilation = self.decompiler.start_decompilation(**params)
            info("Task submitted, waiting for decompilation to finish... ", cr=False)
            decompilation.wait_until_finished()
            print("Done")
            decompilation.save_hll_code(self.get_setting("path"))
            fname = path + '/' + os.path.basename(params["input_file"]) + '.' + params["target_language"]
            ok("Saved as '%s'" % fname)
        except retdec.exceptions.AuthenticationError:
            err("Invalid RetDec API key")
            info("You can store your API key using `gef config`/`gef restore`")
            self.decompiler = None
            return False

        return True


class ChangeFdCommand(GenericCommand):
    """ChangeFdCommand: redirect file descriptor during runtime."""

    _cmdline_ = "hijack-fd"
    _syntax_  = "%s FD_NUM NEW_OUTPUT" % _cmdline_

    def __init__(self):
        super(ChangeFdCommand, self).__init__(prefix=False)
        return

    def do_invoke(self, argv):
        if not is_alive():
            err("No process alive")
            return

        if is_remote_debug():
            err("Cannot run on remote debugging")
            return

        if len(argv)!=2:
            self.usage()
            return

        if not os.access("/proc/%d/fd/%s"%(get_pid(), argv[0]), os.R_OK):
            self.usage()
            return

        old_fd = int(argv[0])
        new_output = argv[1]

        try:
            disable_context()
            res = gdb.execute("""call open("%s", 66, 0666)""" % new_output, to_string=True)
            # Output example: $1 = 3
            new_fd = int(res.split()[2])
            info("Opened '%s' as fd=#%d" % (new_output, new_fd))
            gdb.execute("""call dup2(%d, %d)""" % (new_fd, old_fd), to_string=True)
            info("Duplicated FD #%d %s #%d" % (old_fd, right_arrow, new_fd))
            gdb.execute("""call close(%d)""" % new_fd, to_string=True)
            ok("Success")
            enable_context()
        except:
            err("Failed")
        return


class ProcessIdCommand(GenericCommand):
    """ProcessIdCommand: print the process id of the process being debugged."""

    _cmdline_ = "pid"
    _syntax_  = "%s" % _cmdline_

    @if_gdb_running
    def do_invoke(self, argv):
        print("%d" % get_pid())
        return


class IdaInteractCommand(GenericCommand):
    """IDA Interact: set of commands to interact with IDA."""

    _cmdline_ = "ida-interact"
    _syntax_  = "%s METHOD [ARGS]" % _cmdline_

    def __init__(self):
        super(IdaInteractCommand, self).__init__(prefix=False)
        host, port = "127.0.1.1", 1337
        self.add_setting("host", host)
        self.add_setting("port", port)
        return

    def connect(self):
        """
        Connect to the XML-RPC service.
        """
        host = self.get_setting("host")
        port = self.get_setting("port")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.close()
            sock = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(host, port))
        except:
            err("Failed to connect to '{:s}:{:d}'".format(host, port))
            info("Did you start the IDA script `ida_gef_xmlrpc.py` (https://github.com/hugsy/stuff/blob/master/ida_scripts/ida_gef_xmlrpc.py)?")
            sock = None
        return sock

    def do_invoke(self, argv):
        return self.call(argv)

    def call(self, argv):
        def parsed_arglist(arglist):
            args = []
            for arg in arglist:
                try:
                    # try to solve the argument using gdb
                    argval = gdb.parse_and_eval(arg)
                    argval.fetch_lazy()
                    # check if value is addressable
                    argval = long(argval) if argval.address is None else long(argval.address)
                    args.append( "%#x" % (argval,) )
                except:
                    # if gdb can't parse the value, let ida deal with it
                    args.append(arg)
            return args

        sock = self.connect()
        if sock is None:
            return

        if len(argv)==0 or argv[0] in ("-h", "--help"):
            method_name = argv[1] if len(argv)>1 else None
            self.usage(sock, method_name)
            return

        try:
            method_name = argv[0]
            method = getattr(sock, method_name)
            if len(argv) > 1:
                args = parsed_arglist(argv[1:])
                res = method(*args)
            else:
                res = method()

            if res in (0,  None):
                ok("Success")
                return

            if method_name in ("ImportStruct", "ImportStructs"):
                self.import_structures(res)
            else:
                print(res)
            return
        except Exception as e:
            err(str(e))
            del sock
        return

    def usage(self, sock=None, meth=None):
        super(IdaInteractCommand, self).usage()
        if sock is None:
            return

        if meth is not None:
            print(titlify(meth))
            print(sock.system.methodHelp(meth))
            return

        info("Listing methods: ")
        for m in sock.system.listMethods():
            if m.startswith("system."): continue
            print(titlify(m))
            print(sock.system.methodHelp(m))
        return

    def import_structures(self, structs):
        path = __config__.get("pcustom.struct_path")[0]
        if not os.path.isdir(path):
            gef_makedirs(path)
        for struct_name in structs.keys():
            fullpath = path + "/" + struct_name + ".py"
            with open(fullpath, "wb") as f:
                f.write(b"from ctypes import *\n\nclass Template(Structure):\n    _fields_ = [\n")
                for offset, name, size in structs[struct_name]:
                    if   size == 1: csize = b"c_uint8"
                    elif size == 2: csize = b"c_uint16"
                    elif size == 4: csize = b"c_uint32"
                    elif size == 8: csize = b"c_uint64"
                    else:           csize = b"c_byte * %d" % size
                    f.write(b"""%s("%s", %s),\n""" % (b" "*8, bytes(name, encoding="utf-8"), csize))
                f.write(b"]\n")
        ok("Success, %d structure%s imported"%(len(structs.keys()), "s" if len(structs.keys())>1 else ""))
        return


class SearchPatternCommand(GenericCommand):
    """SearchPatternCommand: search a pattern in memory."""

    _cmdline_ = "search-pattern"
    _syntax_  = "%s PATTERN" % _cmdline_
    _aliases_ = ["grep", ]

    def __init__(self):
        super(SearchPatternCommand, self).__init__(prefix=False)
        return

    def search_pattern_by_address(self, pattern, start_address, end_address):
        """Search a pattern within a range defined by arguments."""
        if PYTHON_MAJOR==3:
            pattern = bytes(pattern, "utf-8")

        length = end_address - start_address
        buf = read_memory(start_address, length)
        locations = []

        for m in re.finditer(pattern, buf):
            try:
                start = start_address + m.start()
                string = read_cstring_from_memory(start)
                end   = start + len(string)
            except UnicodeError:
                string = str(pattern) + "[...]"
                end    = start + len(pattern)
            locations.append( (start, end, string) )
        return locations

    def search_pattern(self, pattern):
        """Search a pattern within the whole userland memory."""
        for section in get_process_maps():
            if not section.permission & Permission.READ: continue
            if section.path == "[vvar]": continue

            start = section.page_start
            end   = section.page_end - 1
            for loc in self.search_pattern_by_address(pattern, start, end):
                print("""{:#x} - {:#x} {:s}  "{:s}" """.format(loc[0], loc[1], right_arrow, Color.pinkify(loc[2])))
        return

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv)!=1:
            self.usage()
            return

        pattern = argv[0]
        info("Searching '{:s}' in memory".format(Color.yellowify(pattern)))
        self.search_pattern(pattern)
        return


class FlagsCommand(GenericCommand):
    """Edit flags in a human friendly way"""

    _cmdline_ = "edit-flags"
    _syntax_  = "%s [(+|-|~)FLAGNAME ...]" % _cmdline_
    _aliases_ = ["flags", ]

    def __init__(self):
        super(FlagsCommand, self).__init__(prefix=False)
        return

    def do_invoke(self, argv):
        for flag in argv:
            if len(flag)<2:
                continue

            action = flag[0]
            name = flag[1:].lower()

            if action not in ('+', '-', '~'):
                err("Invalid action for flag '%s'" % flag)
                continue

            if name not in flags_table().values():
                err("Invalid flag name '%s'" % flag[1:])
                continue

            for k in flags_table().keys():
                if flags_table()[k] == name:
                    off = k
                    break

            old_flag = get_register_ex( flag_register() )
            if action=='+':
                new_flags = old_flag | (1<<off)
            elif action=='-':
                new_flags = old_flag & ~(1<<off)
            else:
                new_flags = old_flag ^ (1<<off)

            gdb.execute("set (%s) = %#x" % (flag_register(), new_flags))

        print(flag_register_to_human())
        return


class ChangePermissionCommand(GenericCommand):
    """Change a page permission. By default, it will change it to RWX."""

    _cmdline_ = "set-permission"
    _syntax_  = "%s LOCATION [PERMISSION]" % _cmdline_
    _aliases_ = ["mprotect", ]

    def __init__(self):
        super(ChangePermissionCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return

    def pre_load(self):
        try:
            import keystone
        except ImportError as ioe:
            msg = "Missing Python `keystone-engine` package. "
            raise GefMissingDependencyException( msg )
        return

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv) not in (1, 2):
            err("Incorrect syntax")
            return

        if len(argv)==2:
            perm = int(argv[1])
        else:
            perm = Permission.READ | Permission.WRITE | Permission.EXECUTE

        loc = int(argv[0], 16)
        sect = process_lookup_address(loc)
        size = sect.page_end - sect.page_start
        original_pc = get_pc()

        info("Generating sys_mprotect(%#x, %#x, '%s') stub for arch %s"%(sect.page_start, size, Permission(value=perm), get_arch()))
        stub = self.get_stub_by_arch(sect.page_start, size, perm)
        if stub is None:
            err("Failed to generate mprotect opcodes")
            return

        info("Saving original code")
        original_code = read_memory(original_pc, len(stub))

        bp_loc = "*%#x"%(original_pc + len(stub))
        info("Setting a restore breakpoint at %s" % bp_loc)
        ChangePermissionBreakpoint(bp_loc, original_code, original_pc)

        info("Overwriting current memory at %#x (%d bytes)" % (loc, len(stub)))
        write_memory(original_pc, stub, len(stub))

        info("Resuming execution")
        gdb.execute("continue")
        return

    def get_stub_by_arch(self, addr, size, perm):
        hi = (addr & 0xffff0000) >> 16
        lo = (addr & 0x0000ffff)

        if is_x86_64():
            _NR_mprotect = 10
            insns = [
                "push rax", "push rdi", "push rsi", "push rdx",
                "mov rax, %d"  % _NR_mprotect,
                "mov rdi, %d"  % addr,
                "mov rsi, %d"  % size,
                "mov rdx, %d"  % perm,
                "syscall",
                "pop rdx", "pop rsi", "pop rdi", "pop rax"
            ]
        elif is_x86_32():
            _NR_mprotect = 125
            insns = [
                "pushad",
                "mov eax, %d"  % _NR_mprotect,
                "mov ebx, %d"  % addr,
                "mov ecx, %d"  % size,
                "mov edx, %d"  % perm,
                "int 0x80",
                "popad",
            ]
        elif is_arm():
            _NR_mprotect = 125
            insns = [
                "push {r0-r2, r7}",
                "mov r0, %d" % addr,
                "mov r1, %d" % size,
                "mov r2, %d" % perm,
                "mov r7, %d" % _NR_mprotect,
                "svc 0",
                "pop {r0-r2, r7}",
            ]
        elif is_mips():
            _NR_mprotect = 4125
            insns = [
                "addi $sp, $sp, -16",
                "sw $v0, 0($sp)", "sw $a0, 4($sp)",
                "sw $a3, 8($sp)", "sw $a3, 12($sp)",
                "li $v0, %d" % _NR_mprotect,
                "li $a0, %d" % addr,
                "li $a1, %d" % size,
                "li $a2, %d" % perm,
                "syscall",
                "lw $v0, 0($sp)", "lw $a1, 4($sp)",
                "lw $a3, 8($sp)", "lw $a3, 12($sp)",
                "addi $sp, $sp, 16",
            ]
        elif is_powerpc() or is_ppc64():
            _NR_mprotect = 125
            insns = [
                # http://www.ibm.com/developerworks/library/l-ppc/index.html
                "addi 1, 1, -16",                 # 1 = r1 = sp
                "stw 0, 0(1)", "stw 3, 4(1)",     # r0 = syscall_code | r3, r4, r5 = args
                "stw 4, 8(1)", "stw 5, 12(1)",
                "li 0, %d" % _NR_mprotect,
                "lis 3, %#x@h" % addr,
                "ori 3, 3, %#x@l" % addr,
                "lis 4, %#x@h" % size,
                "ori 4, 4, %#x@l" % size,
                "li 5, %d" % perm,
                "sc",
                "lwz 0, 0(1)", "lwz 3, 4(1)",
                "lwz 4, 8(1)", "lwz 5, 12(1)",
                "addi 1, 1, 16",
            ]
        elif is_sparc() or is_sparc64():
            _NR_mprotect = 125
            syscall = "t 0x6d" if is_sparc64() else "t 0x10"
            insns = [
                # man 2 syscall
                "add %sp, -16, %sp",
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
                "add %sp, 16, %sp",
                ]
        else:
            raise GefUnsupportedOS("Architecture %s not supported yet" % get_arch())

        arch, mode = get_keystone_arch()
        insns = " ; ".join(insns)
        raw_insns = keystone_assemble(insns, arch, mode, raw=True)
        return raw_insns


class UnicornEmulateCommand(GenericCommand):
    """Unicorn emulate: Use Unicorn-Engine to emulate the behavior of the binary, without affecting the GDB runtime.
    By default the command will emulate only the next instruction, but location and number of instruction can be
    changed via arguments to the command line. By default, it will emulate the next instruction from current PC."""

    _cmdline_ = "unicorn-emulate"
    _syntax_  = "%s [-f LOCATION] [-t LOCATION] [-n NB_INSTRUCTION] [-e] [-h]" % _cmdline_
    _aliases_ = ["emulate", ]

    def __init__(self):
        super(UnicornEmulateCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        self.add_setting("verbose", False)
        self.add_setting("show_disassembly", False)
        return

    def help(self):
        h = "%s\n" % self._syntax_
        h+= "\t-f LOCATION specifies the start address of the emulated run (default $pc).\n"
        h+= "\t-t LOCATION specifies the end address of the emulated run.\n"
        h+= "\t-e /PATH/TO/SCRIPT.py generates a standalone Python script from the current runtime context.\n"
        h+= "\t-n NB_INSTRUCTION indicates the number of instructions to execute (mutually exclusive with `-t` and `-g`).\n"
        h+= "\t-g NB_GADGET indicates the number of gadgets to execute (mutually exclusive with `-t` and `-n`).\n"
        h+= "Additional options can be setup via `gef config unicorn-emulate`\n"
        info(h)
        return

    def pre_load(self):
        try:
            import unicorn
            import capstone
        except ImportError as ie:
            msg = "This command requires the following packages: `unicorn` and `capstone`."
            raise GefMissingDependencyException( msg )
        return

    def post_load(self):
        return

    @if_gdb_running
    def do_invoke(self, argv):
        start_insn = None
        end_insn = -1
        self.nb_insn = -1
        self.until_next_gadget = -1
        to_script = None
        opts, args = getopt.getopt(argv, "f:t:n:e:g:h")
        for o,a in opts:
            if   o == "-f":   start_insn = int(a, 16)
            elif o == "-t":
                end_insn = int(a, 16)
                self.nb_insn = -1
                self.until_next_gadget = -1

            elif o == "-g":
                self.until_next_gadget = int(a)
                self.nb_insn = -1
                end_insn = -1

            elif o == "-n":
                self.nb_insn = int(a)
                self.until_next_gadget = -1
                end_insn = -1

            elif o == "-e":
                to_script = a

            elif o == "-h":
                self.help()
                return

        if start_insn is None:
            start_insn = get_pc()

        if end_insn == -1 and self.nb_insn == -1 and self.until_next_gadget == -1:
            err("No stop condition (-t|-n|-g) defined.")
            return

        self.run_unicorn(start_insn, end_insn, to_script=to_script)
        return

    def get_unicorn_end_addr(self, start_addr, nb):
        dis = gef_disassemble(start_addr, nb+1, True)
        return dis[-1][0]

    def run_unicorn(self, start_insn_addr, end_insn_addr, *args, **kwargs):
        start_regs = {}
        end_regs = {}
        verbose = self.get_setting("verbose") or False
        to_script = kwargs.get("to_script", None)
        content = ""
        arch, mode = get_unicorn_arch(to_string=to_script)
        unicorn_registers = get_unicorn_registers(to_string=to_script)
        fname = get_filename()

        if to_script:
            content+= """#!/usr/bin/python
#
# Emulation script for '%s' from %#x to %#x
#
import readline, code
import capstone, unicorn

regs = {%s}
uc = None

def disassemble(code, addr):
    cs = capstone.Cs(%s, %s)
    for i in cs.disasm(str(code),addr):
        return i

def hook_code(emu, address, size, user_data):
    print(">> Executing instruction at 0x{:x}".format(address))
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))
    return

def interact(emu, regs):
    readline.parse_and_bind('tab: complete')
    vars = globals().copy()
    vars.update(locals())
    code.InteractiveConsole(vars).interact(banner="[+] Spawning Python interactive shell with Unicorn, use `uc` to interact with the emulated session")
    return

def print_regs(emu, regs):
    for r in regs.keys():
        print(">> {:s} = 0x{:x}".format(r, emu.reg_read(regs[r])))
    return

def reset():
""" % (fname, start_insn_addr, end_insn_addr, ",".join(["'%s': %s" % (k.strip(), unicorn_registers[k]) for k in unicorn_registers.keys()]), arch, mode)

        unicorn = sys.modules['unicorn']
        if verbose:
            info("Initializing Unicorn engine")

        if to_script:
            content += "    emu = unicorn.Uc(%s, %s)\n" % (arch, mode)
        else:
            emu = unicorn.Uc(arch, mode)

        if verbose:
            info("Populating registers")

        for r in all_registers():
            gregval = get_register_ex(r)
            if to_script:
                content += "    emu.reg_write(%s, %#x)\n" % (unicorn_registers[r], gregval)
            else:
                emu.reg_write(unicorn_registers[r], gregval)
                start_regs[r] = gregval

        vmmap = get_process_maps()
        if vmmap is None or len(vmmap)==0:
            warn("An error occured when reading memory map.")
            return

        if verbose:
            info("Duplicating memory map")

        # Hack hack hack (- again !!)
        # Because of fs/gs registers used for different purposes (canary and stuff), we map
        # the NULL page as RW- to allow UC to treat instructions dealing with those regs
        # If anybody has a better approach, please send me a PR ;)
        if is_x86_32() or is_x86_64():
            page_sz = resource.getpagesize()
            FS = 0x00
            GS = FS + page_sz
            if to_script:
                content += "    emu.mem_map(%#x, %d, %d)\n" % (FS, page_sz, 3)
                content += "    emu.mem_map(%#x, %d, %d)\n" % (GS, page_sz, 3)
                content += "    emu.reg_write(%s, %#x)\n" % (unicorn_registers['$fs    '], FS)
                content += "    emu.reg_write(%s, %#x)\n" % (unicorn_registers['$gs    '], GS)
            else:
                emu.mem_map(FS, page_sz, 3)
                emu.mem_map(GS, page_sz, 3)
                emu.reg_write(unicorn_registers['$fs    '], FS)
                emu.reg_write(unicorn_registers['$gs    '], GS)


        for sect in vmmap:
            try:
                page_start = sect.page_start
                page_end   = sect.page_end
                size       = sect.size
                perm       = sect.permission
                path       = sect.path

                if to_script:
                    content += "    # Mapping %s: %#x-%#x\n"%(sect.path, page_start, page_end)
                    content += "    emu.mem_map(%#x, %#x, %d)\n" % (page_start, size, perm.value)
                else:
                    emu.mem_map(page_start, size, perm.value)

                if perm & Permission.READ:
                    code = read_memory(page_start, size)
                    if verbose:
                        info("Populating path=%s page=%#x-%#x size=%d perm=%s" % (sect.path,
                                                                                  page_start,
                                                                                  page_end,
                                                                                  size,
                                                                                  perm))

                    if to_script:
                        loc = "/tmp/gef-%s-%#x.raw" % (fname, page_start)
                        with open(loc, "wb") as f:
                            f.write(bytes(code))

                        content += "    emu.mem_write(%#x, open('%s', 'r').read())\n" % (page_start, loc)
                        content += "\n"

                    else:
                        emu.mem_write(page_start, bytes(code))
            except Exception as e:
                warn("Cannot copy page=%#x-%#x : %s" % (page_start, page_end, e))
                continue

        if to_script:
            content += "    emu.hook_add(unicorn.UC_HOOK_CODE, hook_code)\n"
            content += "    return emu\n"
        else:
            emu.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
            emu.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)

        if to_script:
            content += """
def emulate(emu, start_addr, end_addr):
    # Registers initial states
    print_regs(emu, regs)

    try:
        emu.emu_start(start_addr, end_addr)
    except Exception as e:
        emu.emu_stop()
        print('Error: {}'.format(e))

    # Registers final states
    print_regs(emu, regs)
    return


if __name__ == "__main__":
    uc = reset()
    emulate(uc, %#x, %#x)
    interact(uc, regs)

# unicorn-engine script generated by gef
""" % (start_insn_addr, end_insn_addr)

            with open(to_script, 'w') as f:
                f.write(content)

            info("Unicorn script generated as '%s'" % to_script)
            return

        ok("Starting emulation: %#x %s %#x" % (start_insn_addr,
                                               right_arrow,
                                               end_insn_addr))

        try:
            emu.emu_start(start_insn_addr, end_insn_addr)
        except unicorn.UcError as e:
            emu.emu_stop()
            err("An error occured during emulation: %s" % e)
            return

        ok("Emulation ended, showing %s registers:" % Color.redify("tainted"))

        for r in all_registers():
            # ignoring $fs and $gs because of the dirty hack we did to emulate the selectors
            if r in ('$gs    ', '$fs    '): continue

            end_regs[r] = emu.reg_read(unicorn_registers[r])
            tainted = ( start_regs[r] != end_regs[r] )

            if not tainted:
                continue

            msg = ""
            if r != flag_register():
                msg = "%-10s : old=%#.16x || new=%#.16x" % (r.strip(), start_regs[r], end_regs[r])
            else:
                msg = "%-10s : old=%s \n" % (r.strip(), flag_register_to_human(start_regs[r]))
                msg+= "%-16s new=%s" % ("", flag_register_to_human(end_regs[r]),)

            ok(msg)

        return

    def hook_code(self, emu, addr, size, misc):
        if self.nb_insn == 0:
            ok("Stopping emulation on user's demand (max_instructions reached)")
            emu.emu_stop()
            return

        if self.get_setting("show_disassembly"):
            mem = emu.mem_read(addr, size)
            CapstoneDisassembleCommand.disassemble(addr, 1)

        self.nb_insn -= 1
        return

    def hook_block(self, emu, addr, size, misc):
        if self.until_next_gadget == 0:
            ok("Stopping emulation on user's demand (max_gadgets reached)")
            emu.emu_stop()
            return

        if self.get_setting("show_disassembly"):
            addr_s = format_address(addr)
            info("Entering new block at %s" %(addr_s,))

        self.until_next_gadget -= 1
        return


class RemoteCommand(GenericCommand):
    """gef wrapper for the `target remote` command. This command will automatically
    download the target binary in the local temporary directory (defaut /tmp) and then
    source it. Additionally, it will fetch all the /proc/PID/maps and loads all its
    information."""

    _cmdline_ = "gef-remote"
    _syntax_  = "%s [OPTIONS] TARGET" % _cmdline_

    def __init__(self):
        super(RemoteCommand, self).__init__(prefix=False)
        self.handler_connected = False
        return

    def do_invoke(self, argv):
        target = None
        rpid = -1
        update_solib = False
        self.download_all_libs = False
        download_lib = None
        is_extended_remote = False
        opts, args = getopt.getopt(argv, "p:UD:AEh")
        for o,a in opts:
            if   o == "-U":   update_solib = True
            elif o == "-D":   download_lib = a
            elif o == "-A":   self.download_all_libs = True
            elif o == "-E":   is_extended_remote = True
            elif o == "-p":   rpid = int(a)
            elif o == "-h":
                self.help()
                return

        if args is None or len(args)!=1:
            err("A target (HOST:PORT) is always required.")
            return

        if is_extended_remote and rpid < 0:
            err("A PID must be provided (-p <PID>) when using remote-extended mode")
            return

        # lazily install handler on first use
        if not self.handler_connected:
            gdb.events.new_objfile.connect(self.new_objfile_handler)
            self.handler_connected = True

        target = args[0]

        if self.connect_target(target, is_extended_remote) == False:
            return

        # if extended-remote, need to attach
        if is_extended_remote:
            ok("Attaching to %d" % rpid)
            disable_context()
            gdb.execute("attach %d" % rpid)
            enable_context()
        else:
            rpid = get_pid()
            ok("Targeting PID=%d" % rpid)

        self.add_setting("target", target)
        self.setup_remote_environment(rpid, update_solib)

        if not is_remote_debug():
            warn("No remote session active.")
            return

        if self.download_all_libs == True:
            vmmap = get_process_maps()
            success = 0
            for sect in vmmap:
                if sect.path.startswith("/"):
                    _file = download_file(sect.path)
                    if _file is None:
                        err("Failed to download %s" % sect.path)
                    else:
                        success += 1

            ok("Downloaded %d files" % success)

        elif download_lib is not None:
            _file = download_file(download_lib)
            if _file is None:
                err("Failed to download remote file")
                return

            ok("Download success: %s %s %s" % (download_lib, right_arrow, _file))

        if update_solib:
            self.refresh_shared_library_path()

        return

    def new_objfile_handler(self, event):
        """Hook that handles new_objfile events, will update remote environment accordingly"""
        if not is_remote_debug():
            return

        # download newly loaded libraries
        if self.download_all_libs and event.new_objfile.filename.startswith("target:"):
            lib = event.new_objfile.filename[len("target:"):]
            llib = download_file(lib, use_cache=True)
            if llib:
                ok("Download success: %s %s %s" % (lib, right_arrow, llib))

    def setup_remote_environment(self, pid, update_solib=False):
        """Clone the remote environment locally in the temporary directory.
        The command will duplicate the entries in the /proc/<pid> locally and then
        source those information into the current gdb context to allow gef to use
        all the extra commands as it was local debugging."""
        gdb.execute("reset-cache")

        ok("Downloading remote information")
        infos = {}
        for i in ["exe", "maps", "environ", "cmdline"]:
            infos[i] = self.load_target_proc(pid, i)
            if infos[i] is None:
                err("Failed to load memory map of '%s'" % i)
                return

        if not os.access(infos["exe"], os.R_OK):
            err("Source binary is not readable")
            return

        directory  = '%s/gef' % (tempfile.gettempdir())
        gdb.execute("file %s" % infos["exe"])

        self.add_setting("root", directory)

        ok("Remote information loaded, remember to clean '%s' when your session is over" % tempfile.gettempdir())
        return

    def connect_target(self, target, is_extended_remote):
        """Connect to remote target and get symbols. To prevent `gef` from requesting information
        not fetched just yet, we disable the context disable when connection was successful."""
        disable_context()
        try:
            gdb.execute("target {0} {1}".format("extended-remote" if is_extended_remote else "remote",
                                                target))
            ok("Connected to '%s'" % target)
            ret = True
        except Exception as e:
            err("Failed to connect to %s: %s" % (target, str(e)))
            ret = False
        enable_context()
        return ret


    def load_target_proc(self, pid, info):
        """Download one item from /proc/pid"""
        remote_name = "/proc/{:d}/{:s}".format(pid, info)
        return download_file(remote_name)


    def refresh_shared_library_path(self):
        dirs = [r for r, d, f in os.walk( self.get_setting("root") )]
        path = ":".join(dirs)
        gdb.execute("set solib-search-path %s" % (path,))
        return


    def help(self):
        h = "%s\n" % self._syntax_
        h+= "\t   TARGET (mandatory) specifies the host:port, serial port or tty to connect to.\n"
        h+= "\t-U will update gdb `solib-search-path` attribute to include the files downloaded from server (default: False).\n"
        h+= "\t-A will download *ALL* the remote shared libraries and store them in the new environment. This command can take a few minutes to complete (default: False).\n"
        h+= "\t-D LIB will download the remote library called LIB.\n"
        h+= "\t-E Use 'extended-remote' to connect to the target.\n"
        h+= "\t-p PID (mandatory if -E is used) specifies PID of the debugged process on gdbserver's end.\n"
        info(h)
        return


class NopCommand(GenericCommand):
    """Patch the instruction pointed by parameters with NOP. If the return option is
    specified, it will set the return register to the specific value."""

    _cmdline_ = "nop"
    _syntax_  = "%s [-r VALUE] [-p] [-h] [LOCATION]" % _cmdline_


    def __init__(self):
        super(NopCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return


    def get_insn_size(self, addr):
        res = gef_disassemble(addr, 1, True)
        insns = [ x[0] for x in res ]
        return insns[1] - insns[0]


    def do_invoke(self, argv):
        retval = None
        perm_mode = False
        opts, args = getopt.getopt(argv, "r:ph")
        for o,a in opts:
            if   o == "-r":
                retval = long(a, 16)
            elif o == "-p":
                perm_mode = True
            elif o == "-h":
                self.help()
                return

        if perm_mode:
            if len(args)==0:
                err("Missing location")
                return
            self.permanent_patch(args[0], retval)
            return

        if len(args):
            loc = parse_address(args[0])
        else:
            loc = get_pc()

        self.onetime_patch(loc, retval)
        return


    def help(self):
        m = "%s\n" % self._syntax_
        m+= "  LOCATION\taddress/symbol to patch\n"
        m+= "  -r VALUE\tset the return register to VALUE (ex. 0x00, 0xffffffff)\n"
        m+= "  -p \t\tmake this patch permanent for the whole GDB session\n"
        m+= "  -h \t\tprint this help\n"
        info(m)
        return


    @if_gdb_running
    def onetime_patch(self, loc, retval):
        size = self.get_insn_size( loc )
        nops = nop_insn()

        if len(nops) > size:
            err("Cannot patch instruction at %#x (nop_size is:%d,insn_size is:%d)" % (loc, len(nops), size))
            return

        if len(nops) < size:
            warn("Adjusting NOPs to size %d" % size)
            while len(nops) < size:
                nops += nop_insn()

        if len(nops) != size:
            err("Cannot patch instruction at %#x (unexpected NOP length)" % (loc))
            return

        ok("Patching %d bytes from %s" % (size, format_address(loc)))
        write_memory(loc, nops, size)

        if retval is not None:
            reg = return_register()
            addr = '*'+format_address(loc)
            SetRegisterBreakpoint(addr, reg, retval)
        return


    def permanent_patch(self, loc, retval):
        PatchBreakpoint(loc, retval)
        return


class CapstoneDisassembleCommand(GenericCommand):
    """Use capstone disassembly framework to disassemble code."""

    _cmdline_ = "capstone-disassemble"
    _syntax_  = "%s [-n LENGTH] [-t opt] [LOCATION]" % _cmdline_
    _aliases_ = ["cs-dis", ]


    def pre_load(self):
        try:
            import capstone
        except ImportError as ie:
            msg = "Missing Python `capstone` package. "
            raise GefMissingDependencyException( msg )
        return


    def __init__(self):
        super(CapstoneDisassembleCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        location, length = get_pc(), 0x10
        opts, args = getopt.getopt(argv, 'n:x:')
        for o,a in opts:
            if  o == "-n":
                length = long(a)
            elif o == "-x":
                k, v = a.split(":", 1)
                self.add_setting(k, v)

        if len(args):
            location = parse_address( args[0] )

        kwargs = {}
        if self.has_setting("arm_thumb"):
            kwargs["arm_thumb"] = True

        if self.has_setting("mips_r6"):
            kwargs["mips_r6"] = True

        CapstoneDisassembleCommand.disassemble(location, length, **kwargs)
        return


    @staticmethod
    def disassemble(location, max_inst, *args, **kwargs):
        capstone    = sys.modules['capstone']
        arch, mode  = get_capstone_arch()
        cs          = capstone.Cs(arch, mode)
        cs.detail   = True

        page_start  = align_address_to_page(location)
        offset      = location - page_start
        inst_num    = 0
        pc          = get_pc()

        code        = kwargs.get("code", None)
        if code is None:
            code  = read_memory(location, DEFAULT_PAGE_SIZE-offset-1)

        code = bytes(code)

        for insn in cs.disasm(code, location):
            m = Color.colorify(format_address(insn.address), attrs="bold blue") + "\t"

            if (insn.address == pc):
                m+= CapstoneDisassembleCommand.__cs_analyze_insn(insn, arch, True)
            else:
                m+= Color.greenify("%s" % insn.mnemonic) + "\t"
                m+= Color.yellowify("%s" % insn.op_str)

            print(m)
            inst_num += 1
            if inst_num == max_inst:
                break

        return


    @staticmethod
    def __cs_analyze_insn(insn, arch, is_pc=True):
        cs = sys.modules['capstone']

        m = ""
        m+= Color.greenify("%s" % insn.mnemonic)
        m+= "\t"
        m+= Color.yellowify("%s" % insn.op_str)

        if is_pc:
            m+= Color.redify("\t"+left_arrow+" $pc ")

        m+= '\n' + '\t'*5

        # implicit read
        if len(insn.regs_read) > 0:
            m+= "Read:[%s] " % ','.join([insn.reg_name(x) for x in insn.regs_read])
            m+= '\n' + '\t'*5

        # implicit write
        if len(insn.regs_write) > 0:
            m+= "Write:[%s] " % ','.join([insn.reg_name(x) for x in insn.regs_write])
            m+= '\n' + '\t'*5

        if   is_x86_32():  reg, imm, mem = cs.x86.X86_OP_REG, cs.x86.X86_OP_IMM, cs.x86.X86_OP_MEM
        elif is_x86_64():  reg, imm, mem = cs.x86.X86_OP_REG, cs.x86.X86_OP_IMM, cs.x86.X86_OP_MEM
        elif is_powerpc(): reg, imm, mem = cs.ppc.PPC_OP_REG, cs.ppc.PPC_OP_IMM, cs.ppc.PPC_OP_MEM
        elif is_mips():    reg, imm, mem = cs.mips.MIPS_OP_REG, cs.mips.MIPS_OP_IMM, cs.mips.MIPS_OP_MEM
        elif is_sparc():   reg, imm, mem = cs.sparc.SPARC_OP_REG, cs.sparc.SPARC_OP_IMM, cs.sparc.SPARC_OP_MEM
        elif is_sparc64(): reg, imm, mem = cs.sparc.SPARC_OP_REG, cs.sparc.SPARC_OP_IMM, cs.sparc.SPARC_OP_MEM
        elif is_arm():     reg, imm, mem = cs.arm.ARM_OP_REG, cs.arm.ARM_OP_IMM, cs.arm.ARM_OP_MEM
        elif is_aarch64(): reg, imm, mem = cs.arm.ARM_OP_REG, cs.arm.ARM_OP_IMM, cs.arm.ARM_OP_MEM

        # operand information
        for op in insn.operands:
            if op.type == reg:
                m+="REG=%s " % (insn.reg_name(op.value.reg),)
            if op.type == imm:
                m+="IMM=%#x " % (op.value.imm,)
            if op.type == mem:
                if op.value.mem.disp > 0:
                    m+="MEM=%s+%#x " % (insn.reg_name(op.value.mem.base), op.value.mem.disp,)
                elif op.value.mem.disp < 0:
                    m+="MEM=%s%#x " % (insn.reg_name(op.value.mem.base), op.value.mem.disp,)

            m+= '\n' + '\t'*5

        return m


class GlibcHeapCommand(GenericCommand):
    """Base command to get information about the Glibc heap structure."""

    _cmdline_ = "heap"
    _syntax_  = "%s (chunk|bins|arenas)" % _cmdline_

    def do_invoke(self, argv):
        self.usage()
        return


class GlibcHeapArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap arenas"
    _syntax_  = "%s" % _cmdline_

    def __init__(self):
        super(GlibcHeapArenaCommand, self).__init__(prefix=False)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        ok("Listing active arena(s):")
        try:
            arena = GlibcArena("main_arena")
        except:
            info("Could not find Glibc main arena")
            return

        while True:
            print("%s" % (arena,))
            arena = arena.get_next()
            if arena is None:
                break

        return

class GlibcHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk.
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _cmdline_ = "heap chunk"
    _syntax_  = "%s MALLOCED_LOCATION" % _cmdline_

    def __init__(self):
        super(GlibcHeapChunkCommand, self).__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv) < 1:
            err("Missing chunk address")
            self.usage()
            return

        addr = long(gdb.parse_and_eval( argv[0] ))
        chunk = GlibcChunk(addr)
        chunk.pprint()
        return

class GlibcHeapBinsCommand(GenericCommand):
    """Display information on the bins on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _bins_type_ = [ "fast", "unsorted", "small", "large"]
    _cmdline_ = "heap bins"
    _syntax_  = "%s [%s]" % (_cmdline_, '|'.join(_bins_type_))

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv)==0:
            for bin_t in GlibcHeapBinsCommand._bins_type_:
                gdb.execute("heap bins %s" % bin_t)
            return

        bin_t = argv[0]
        if bin_t not in GlibcHeapBinsCommand._bins_type_:
            self.usage()
            return

        gdb.execute("heap bins %s" % bin_t)
        return

    @staticmethod
    def pprint_bin(arena_addr, bin_idx):
        arena = GlibcArena(arena_addr)
        fw, bk = arena.bin(bin_idx)

        ok("Found base for bin({:d}): fw={:#x}, bk={:#x}".format(bin_idx, fw, bk))
        if bk == fw and ((int(arena)&~0xFFFF) == (bk&~0xFFFF)):
            ok("Empty")
            return

        m = ""
        head = GlibcChunk(bk+2*arena.get_arch()).get_fwd_ptr()
        while fw != head:
            chunk = GlibcChunk(fw+2*arena.get_arch())
            m+= "{:s}  {:s}  ".format(right_arrow, str(chunk))
            fw = chunk.get_fwd_ptr()

        print(m)
        return

class GlibcHeapFastbinsYCommand(GenericCommand):
    """Display information on the fastbinsY on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _cmdline_ = "heap bins fast"
    _syntax_  = "%s [ARENA_LOCATION]" % _cmdline_

    def __init__(self):
        super(GlibcHeapFastbinsYCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv)==1:
            arena = GlibcArena('*'+argv[0])
        else:
            arena = GlibcArena("main_arena")

        if arena is None:
            err("No main_arena (linked statically?)")
            return

        print(titlify("Information on FastBins of arena %#x" % int(arena)))
        for i in range(10):
            m = "Fastbin[{:d}] ".format(i,)
            # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1680
            chunk = arena.fastbin(i)

            while True:
                if chunk is None:
                    m+= "0x00"
                    break

                try:
                    m+= "{:s}  {:s}  ".format(right_arrow, str(chunk))
                    next_chunk = chunk.get_fwd_ptr()
                    if next_chunk == 0x00:
                        break

                    chunk = GlibcChunk(next_chunk, from_base=True)
                except gdb.MemoryError:
                    break

            print(m)
        return

class GlibcHeapUnsortedBinsCommand(GenericCommand):
    """Display information on the Unsorted Bins of an arena (default: main_arena).
    See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689"""

    _cmdline_ = "heap bins unsorted"
    _syntax_  = "%s [ARENA_LOCATION]" % _cmdline_

    def __init__(self):
        super(GlibcHeapUnsortedBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        arena_addr =  "*%#x"%int(argv[0],16) if len(argv)==1 else "main_arena"
        print(titlify("Information on Unsorted Bin of arena '{:s}'".format(arena_addr)))
        GlibcHeapBinsCommand.pprint_bin(arena_addr, 0)
        return

class GlibcHeapSmallBinsCommand(GenericCommand):
    """Convience command for viewing small bins"""

    _cmdline_ = "heap bins small"
    _syntax_  = "%s [ARENA_LOCATION]" % _cmdline_

    def __init__(self):
        super(GlibcHeapSmallBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        arena_addr = "*%#x"%int(argv[0],16) if len(argv)==1 else "main_arena"
        print(titlify("Information on Small Bins of arena '{:s}'".format(arena_addr)))
        for i in range(1, 64):
            GlibcHeapBinsCommand.pprint_bin(arena_addr, i)
        return

class GlibcHeapLargeBinsCommand(GenericCommand):
    """Convience command for viewing large bins"""

    _cmdline_ = "heap bins large"
    _syntax_  = "%s [ARENA_LOCATION]" % _cmdline_

    def __init__(self):
        super(GlibcHeapLargeBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        return

    @if_gdb_running
    def do_invoke(self, argv):
        arena_addr = "*%#x"%int(argv[0],16) if len(argv)==1 else "main_arena"
        print(titlify("Information on Large Bins of arena '{:s}'".format(arena_addr)))
        for i in range(64, 127):
            GlibcHeapBinsCommand.pprint_bin(arena_addr, i)
        return


class AliasCommand(GenericCommand):
    """GEF defined aliases"""

    _cmdline_ = "gef-alias"
    _syntax_  = "%s (set|show|do|unset)" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if argc == 0:
            err("Missing action")
            self.usage()
        return

class AliasSetCommand(GenericCommand):
    """GEF add alias command"""
    _cmdline_ = "gef-alias set"
    _syntax_  = "%s NAME CMD1 [; CMD2] [; CMDN]" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 2:
            err("Requires at least 2 params")
            return
        alias_name = argv[0]
        alias_cmds  = " ".join(argv[1:]).split(";")

        if alias_name in list( __aliases__.keys() ):
            warn("Replacing alias '%s'" % alias_name)
            __aliases__[ alias_name ] = alias_cmds
            ok("'%s': '%s'" % (alias_name, "; ".join(alias_cmds)))
        return

class AliasUnsetCommand(GenericCommand):
    """GEF remove alias command"""
    _cmdline_ = "gef-alias unset"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if len(argv) != 1:
            err("'%s' requires 1 param" % self._cmdline_)
            return
        if  argv[1] in  __aliases__:
            del __aliases__[ argv[1] ]
        else:
            err("'%s' not an alias" % argv[1])
        return

class AliasShowCommand(GenericCommand):
    """GEF show alias command"""
    _cmdline_ = "gef-alias show"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        for alias_name in list( __aliases__.keys() ):
            print("'%s'\t'%s'" % (alias_name, ";".join(__aliases__[alias_name])))
        return

class AliasDoCommand(GenericCommand):
    """GEF do alias command"""
    _cmdline_ = "gef-alias do"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)
        if argc != 1:
            err("'%s do' requires 1 param")
            return

        alias_name = argv[0]
        if alias_name not in list( __aliases__.keys() ):
            err("No alias '%s'" % alias_name)
            return

        alias_cmds = __aliases__[alias_name]
        for cmd in alias_cmds:
            try:
                if " >> " in cmd:
                    cmd, outfile = cmd.split(" >> ")
                    cmd = cmd.strip()
                    outfile = outfile.strip()

                    with open(outfile, "a") as f:
                        lines_out = gdb.execute(cmd, to_string=True)
                        f.write(lines_out)

                elif " > " in cmd:
                    cmd, outfile = cmd.split(" > ")
                    cmd = cmd.strip()
                    outfile = outfile.strip()

                    with open(outfile, "w") as f:
                        lines_out = gdb.execute(cmd, to_string=True)
                        f.write(lines_out)

                else:
                    gdb.execute(cmd)

            except:
                continue

        return


class SolveKernelSymbolCommand(GenericCommand):
    """Solve kernel symbols from kallsyms table."""

    _cmdline_ = "ksymaddr"
    _syntax_  = "%s SymbolToSearch" % _cmdline_

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
                        ok("Found matching symbol for '%s' at %#x (type=%s)" % (sym, symaddr, symtype))
                        found = True
                    if sym in symname:
                        warn("Found partial match for '%s' at %#x (type=%s): %s" % (sym, symaddr, symtype, symname))
                        found = True
                except ValueError:
                    pass

        if not found:
            err("No match for '%s'" % sym)
        return


class DetailRegistersCommand(GenericCommand):
    """Display full details on one, many or all registers value from current architecture."""

    _cmdline_ = "registers"
    _syntax_  = "%s [Register1] [Register2] ... [RegisterN]" % _cmdline_

    @if_gdb_running
    def do_invoke(self, argv):
        regs = []

        if len(argv) > 0:
            regs = [ reg for reg in all_registers() if reg.strip() in argv ]
        else:
            regs = all_registers()

        for regname in regs:
            reg = gdb.parse_and_eval(regname)
            if reg.type.code == gdb.TYPE_CODE_VOID:
                continue

            line = Color.colorify(regname, attrs="bold red") + ": "

            if str(reg.type) == 'builtin_type_sparc_psr':  # ugly but more explicit
                line+= "%s" % reg
                continue

            if reg.type.code == gdb.TYPE_CODE_FLAGS:
                desc_flag = flag_register()
                line+= "%s" % (Color.boldify(str(reg))) if desc_flag == "" else desc_flag
                continue

            addr = align_address( long(reg) )

            line+= Color.colorify(format_address(addr), attrs="bold blue")
            addrs = DereferenceCommand.dereference_from(addr)

            if len(addrs) > 1:
                sep = " %s " % right_arrow
                line+= sep + sep.join(addrs[1:])

            print(line)

        return


class ShellcodeCommand(GenericCommand):
    """ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to
    download shellcodes"""

    _cmdline_ = "shellcode"
    _syntax_  = "%s (search|get)" % _cmdline_


    def do_invoke(self, argv):
        self.usage()
        return


class ShellcodeSearchCommand(GenericCommand):
    """Search patthern in shellcodes database."""

    _cmdline_ = "shellcode search"
    _syntax_  = "%s <pattern1> <pattern2>" % _cmdline_
    _aliases_ = ["sc-search",]

    api_base = "http://shell-storm.org"
    search_url = api_base + "/api/?s="


    def do_invoke(self, argv):
        if len(argv) == 0:
            err("Missing pattern to search")
            self.usage()
        else:
            self.search_shellcode(argv)
        return


    def search_shellcode(self, search_options):
        # API : http://shell-storm.org/shellcode/
        args = "*".join(search_options)
        http = urlopen(self.search_url + args)

        if http.getcode() != 200:
            err("Could not query search page: got %d" % http.getcode())
            return

        ret = http.read()
        if PYTHON_MAJOR == 3:
            ret = str( ret, encoding="ascii" )

        # format: [author, OS/arch, cmd, id, link]
        lines = ret.split("\n")
        refs = [ line.split("::::") for line in lines ]

        if len(refs) > 0:
            info("Showing matching shellcodes")
            info("\t".join(["Id", "Platform", "Description"]))
            for ref in refs:
                try:
                    auth, arch, cmd, sid, link = ref
                    print("\t".join([sid, arch, cmd]))
                except ValueError:
                    continue

            info("Use `shellcode get <id>` to fetch shellcode")
        return


class ShellcodeGetCommand(GenericCommand):
    """Download shellcode from shellcodes database"""

    _cmdline_ = "shellcode get"
    _syntax_  = "%s <shellcode_id>" % _cmdline_
    _aliases_ = ["sc-get",]

    api_base = "http://shell-storm.org"
    get_url = api_base + "/shellcode/files/shellcode-%d.php"


    def do_invoke(self, argv):
        if len(argv) != 1:
            err("Missing pattern to search")
            self.usage()
            return

        if not argv[0].isdigit():
            err("ID is not a digit")
            self.usage()
            return

        self.get_shellcode(long(argv[0]))
        return


    def get_shellcode(self, sid):
        http = urlopen(self.get_url % sid)

        if http.getcode() != 200:
            err("Could not query search page: got %d" % http.getcode())
            return

        ret  = http.read()
        if PYTHON_MAJOR == 3:
            ret = str( ret, encoding="ascii" )

        info("Downloading shellcode id=%d" % sid)
        fd, fname = tempfile.mkstemp(suffix=".txt", prefix="sc-", text=True, dir='/tmp')
        data = ret.split("\n")[7:-11]
        buf = "\n".join(data)
        buf = HTMLParser().unescape( buf )

        if PYTHON_MAJOR == 3:
            buf = bytes(buf, "UTF-8")

        os.write(fd, buf)
        os.close(fd)
        info("Shellcode written as '%s'" % fname)
        return


class RopperCommand(GenericCommand):
    """Ropper (http://scoding.de/ropper) plugin"""

    _cmdline_ = "ropper"
    _syntax_  = "%s  [OPTIONS]" % _cmdline_


    def __init__(self):
        super(RopperCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        return

    def pre_load(self):
        try:
            import ropper
        except ImportError as ie:
            msg = "Missing Python `ropper` package. "
            raise GefMissingDependencyException( msg )
        return


    def do_invoke(self, argv):
        ropper = sys.modules['ropper']
        argv.append('--file')
        argv.append(get_filepath())
        try:
            ropper.start(argv)
        except SystemExit:
            return


class ROPgadgetCommand(GenericCommand):
    """ROPGadget (http://shell-storm.org/project/ROPgadget) plugin"""

    _cmdline_ = "ropgadget"
    _syntax_  = "%s  [OPTIONS]" % _cmdline_


    def __init__(self):
        super(ROPgadgetCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        return

    def pre_load(self):
        try:
            import ropgadget

        except ImportError as ie:
            msg = "Missing Python `ropgadget` package. "
            raise GefMissingDependencyException( msg )

        return


    def do_invoke(self, argv):
        class FakeArgs(object):
            all        = None
            binary     = None
            string     = None
            opcode     = None
            memstr     = None
            console    = None
            norop      = None
            nojop      = None
            depth      = 10
            nosys      = None
            range      = "0x00-0x00"
            badbytes   = None
            only       = None
            filter     = None
            ropchain   = None
            offset     = 0x00
            outfile    = None
            thumb      = None
            rawArch    = None
            rawMode    = None
            multibr    = None


        ropgadget = sys.modules['ropgadget']
        args = FakeArgs()
        if self.parse_args(args, argv):
            ropgadget.core.Core( args ).analyze()
        return


    def parse_args(self, args, argv):
        #
        # options format is 'option_name1=option_value1'
        #
        def __usage__():
            arr = [ x for x in dir(args) if not x.startswith("__") ]
            info("Valid options for %s are:\n%s" % (self._cmdline_, ", ".join(arr)))
            return

        for opt in argv:
            if opt in ("?", "h", "help"):
                __usage__()
                return False

            try:
                name, value = opt.split("=")
            except ValueError:
                err("Invalid syntax for argument '{0:s}', should be '{0:s}=<value>'".format(opt) )
                __usage__()
                return False

            if hasattr(args, name):
                if name == "console":
                    continue
                elif name == "depth":
                    value = long(value)
                    depth = value
                    info("Using depth %d" % depth)
                elif name == "range":
                    off_min = long(value.split('-')[0], 16)
                    off_max = long(value.split('-')[1], 16)
                    if off_max < off_min:
                        raise ValueError("%#x must be higher that %#x" % (off_max, off_min))
                    info("Using range [%#x:%#x] (%ld bytes)" % (off_min, off_max, (off_max-off_min)))

                setattr(args, name, value)

            else:
                err("'%s' is not a valid ropgadget option" % name)
                __usage__()
                return False

        if getattr(args, "binary") is None:
            setattr(args, "binary", get_filepath())

        info("Using binary: %s" % args.binary)
        return True


class FileDescriptorCommand(GenericCommand):
    """Enumerate file descriptors opened by process."""

    _cmdline_ = "fd"
    _syntax_  = "%s" % _cmdline_

    @if_gdb_running
    def do_invoke(self, argv):
        if is_remote_debug():
            warn("'%s' cannot be used on remote debugging" % self._cmdline_)
            return

        pid = get_pid()
        path = "/proc/%d/fd" % (pid)

        for fname in os.listdir(path):
            fullpath = path+"/"+fname
            if os.path.islink(fullpath):
                info("- %s %s %s" % (fullpath, right_arrow, os.readlink(fullpath)))

        return


class AssembleCommand(GenericCommand):
    """Inline code assemble. Architecture can be set in GEF runtime config (default is
    x86). """

    _cmdline_ = "assemble"
    _syntax_  = "%s [-a ARCH] [-m MODE] [-e] [-s] [-l LOCATION] instruction;[instruction;...instruction;])" % _cmdline_
    _aliases_ = ["asm", ]

    def __init__(self, *args, **kwargs):
        super(AssembleCommand, self).__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def pre_load(self):
        try:
            import keystone
        except ImportError as ioe:
            msg = "Missing Python `keystone-engine` package. "
            raise GefMissingDependencyException( msg )
        return

    def do_invoke(self, argv):
        keystone = sys.modules["keystone"]
        arch_s, mode_s, big_endian, as_shellcode, write_to_location = None, None, False, False, None
        opts, args = getopt.getopt(argv, "a:m:l:esh")
        for o,a in opts:
            if o=="-a": arch_s = a.upper()
            if o=="-m": mode_s = a.upper()
            if o=="-e": big_endian = True
            if o=="-s": as_shellcode = True
            if o=="-l": write_to_location = long(gdb.parse_and_eval(a))
            if o=="-h":
                self.usage()
                return

        if len(args)==0:
            return

        if (arch_s, mode_s)==(None, None):
            if is_alive():
                arch_s, mode_s = get_arch(), ""
                endian_s = "big" if is_big_endian() else "little"
                arch, mode = get_keystone_arch()
            else:
                # if not alive, defaults to x86-32
                arch_s = "X86"
                mode_s = "32"
                endian_s = "little"
                arch, mode = get_keystone_arch(arch=arch_s, mode=mode_s, endian=False)
        else:
            arch, mode = get_keystone_arch(arch=arch_s, mode=mode_s, endian=big_endian)
            endian_s = "big" if big_endian else "little"

        insns = " ".join(args)
        insns = [x.strip() for x in insns.split(";") if x is not None]
        end = ""

        info("Assembling {} instruction{} for {} ({} endian)".format(len(insns),
                                                                     "s" if len(insns)>1 else "",
                                                                     ":".join([arch_s, mode_s]),
                                                                     endian_s))

        if as_shellcode:
            print("""sc="" """)

        raw = b""
        for insn in insns:
            res = keystone_assemble(insn, arch, mode, raw=True)
            if res is None:
                print("(Invalid)")
                continue

            if write_to_location:
                raw+= res
                continue

            s = binascii.hexlify(res)
            res = b"\\x" + b"\\x".join( [s[i:i+2] for i in range(0, len(s), 2)] )
            res = res.decode("utf-8")

            if as_shellcode:
                res = """sc+="{0:s}" """.format(res)

            print("{0:60s} # {1}".format(res, insn))

        if write_to_location:
            l = len(raw)
            info("Overwriting %d bytes at %s" % (l, format_address(write_to_location)))
            write_memory(write_to_location, raw, len(raw))
        return


class ProcessListingCommand(GenericCommand):
    """List and filter process."""

    _cmdline_ = "process-search"
    _syntax_  = "%s [PATTERN]" % _cmdline_
    _aliases_ = ["ps", ]

    def __init__(self):
        super(ProcessListingCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        self.add_setting("ps_command", "/bin/ps auxww")
        return

    def do_invoke(self, argv):
        processes = self.ps()
        do_attach = False
        smart_scan = False

        opts, args = getopt.getopt(argv, "as")
        for o,a in opts:
            if o=="-a": do_attach  = True
            if o=="-s": smart_scan = True

        pattern = re.compile("^.*$") if len(args)==0 else re.compile(args[0])

        for process in processes:
            pid = int(process["pid"])
            command = process['command']

            if not re.search(pattern, command):
                continue

            if smart_scan:
                if command.startswith("[") and command.endswith("]"): continue
                if command.startswith("socat "): continue
                if command.startswith("grep "): continue
                if command.startswith("gdb "): continue

            if len(args) and do_attach:
                ok("Attaching to process='%s' pid=%d" % (process["command"], pid))
                gdb.execute("attach %d" % pid)
                return None

            line = [ process[i] for i in ("pid", "user", "cpu", "mem", "tty", "command") ]
            print ( '\t\t'.join(line) )

        return None


    def ps(self):
        processes = []
        output = gef_execute_external(self.get_setting("ps_command").split(), True).splitlines()
        names = [x.lower().replace('%','') for x in output[0].split()]

        for line in output[1:]:
            fields = line.split()
            t = {}

            for i in range(len(names)):
                if i==len(names)-1:
                    t[ names[i] ] = ' '.join(fields[i:])
                else:
                    t[ names[i] ] = fields[i]

            processes.append(t)

        return processes


class ElfInfoCommand(GenericCommand):
    """Display ELF header informations."""

    _cmdline_ = "elf-info"
    _syntax_  = "%s" % _cmdline_

    def __init__(self, *args, **kwargs):
        super(ElfInfoCommand, self).__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return


    def do_invoke(self, argv):
        # http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        classes = { 0x01: "32-bit",
                    0x02: "64-bit",
        }
        endianness = { 0x01: "Little-Endian",
                       0x02: "Big-Endian",
        }
        osabi = { 0x00: "System V",
                  0x01: "HP-UX",
                  0x02: "NetBSD",
                  0x03: "Linux",
                  0x06: "Solaris",
                  0x07: "AIX",
                  0x08: "IRIX",
                  0x09: "FreeBSD",
                  0x0C: "OpenBSD",
        }

        types = { 0x01: "Relocatable",
                  0x02: "Executable",
                  0x03: "Shared",
                  0x04: "Core"
        }

        machines = { 0x02: "SPARC",
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

        filename = argv[0] if len(argv) > 0 else get_filepath()
        if filename is None:
            return

        elf = get_elf_headers(filename)
        if elf is None:
            return

        data = [("Magic", "{0!s}".format( hexdump(struct.pack(">I",elf.e_magic), show_raw=True))),
                ("Class", "{0:#x} - {1}".format(elf.e_class, classes[elf.e_class])),
                ("Endianness", "{0:#x} - {1}".format(elf.e_endianness, endianness[ elf.e_endianness ])),
                ("Version", "{:#x}".format(elf.e_eiversion)),
                ("OS ABI", "{0:#x} - {1}".format(elf.e_osabi, osabi[ elf.e_osabi])),
                ("ABI Version", "{:#x}".format(elf.e_abiversion)),
                ("Type", "{0:#x} - {1}".format(elf.e_type, types[elf.e_type]) ),
                ("Machine", "{0:#x} - {1}".format(elf.e_machine, machines[elf.e_machine])),
                ("Program Header Table" , "{}".format(format_address(elf.e_phoff))),
                ("Section Header Table" , "{}".format( format_address(elf.e_shoff) )),
                ("Header Table" , "{}".format( format_address(elf.e_phoff))),
                ("ELF Version", "{:#x}".format( elf.e_version)),
                ("Header size" , "{0} ({0:#x})".format(elf.e_ehsize)),
                ("Entry point", "{}".format( format_address(elf.e_entry) )),
              ]

        for title, content in data:
            print("{:<30}: {}".format(Color.boldify(title), content))
        return


class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it."""

    _cmdline_ = "entry-break"
    _syntax_  = "%s" % _cmdline_
    _aliases_ = ["start-break", ]

    def __init__(self):
        super(EntryPointBreakCommand, self).__init__(prefix=False)
        return

    def do_invoke(self, argv):
        if get_filepath() is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        syms = ["main", "__libc_start_main", "__uClibc_main"]
        for sym in syms:
            try:
                value = gdb.parse_and_eval(sym)
                info("Breaking at '%s'" % value)
                gdb.execute("tbreak %s" % sym, to_string=True)
                gdb.execute("run")
                return

            except gdb.error as gdb_error:
                if 'The "remote" target does not support "run".' in str(gdb_error):
                    # this case can happen when doing remote debugging
                    gdb.execute("continue")
                    return
                # otherwise, simply continue with next symbol
                warn("Could not solve `%s` symbol" % sym)
                continue

        # break at entry point - should never fail
        elf = get_elf_headers()
        if elf is None:
            return

        value = elf.e_entry
        if value:
            info("Breaking at entry-point: %#x" % value)
            gdb.execute("tbreak *%#x" % value, to_string=True)
            info("Starting execution")
            gdb.execute("run")
            return

        return



class ContextCommand(GenericCommand):
    """Display execution context."""

    _cmdline_ = "context"
    _syntax_  = "%s" % _cmdline_
    _aliases_ = ["ctx",]

    old_registers = {}

    def __init__(self):
        super(ContextCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=False)
        self.add_setting("enable", True)
        self.add_setting("show_stack_raw", False)
        self.add_setting("nb_lines_stack", 8)
        self.add_setting("nb_lines_backtrace", 3)
        self.add_setting("nb_lines_code", 5)
        self.add_setting("clear_screen", False)

        self.add_setting("show_registers", True)
        self.add_setting("show_stack", True)
        self.add_setting("show_code", True)
        self.add_setting("show_trace", True)

        if "capstone" in list( sys.modules.keys() ):
            self.add_setting("use_capstone", False)
        return


    @if_gdb_running
    def do_invoke(self, argv):
        if not self.get_setting("enable"):
            return

        if self.get_setting("clear_screen"):
            clear_screen()

        self.tty_rows, self.tty_columns = get_terminal_size()

        self.context_regs()
        self.context_stack()
        self.context_code()
        self.context_source()
        self.context_trace()
        self.context_title('')
        self.update_registers()
        return

    def context_title(self, m):
        trail = horizontal_line*2
        title = "[{}]{}".format(m,trail) if len(m) else "{}".format(trail)
        title = horizontal_line*(self.tty_columns-len(title)) + title
        print(Color.colorify(title, attrs="bold blue"))
        return

    def context_regs(self):
        if self.get_setting("show_registers")==False: return

        self.context_title("registers")

        l = max(map(len, all_registers()))
        l+= 5
        l+= 16 if is_elf64() else 8
        nb = math.floor(get_terminal_size()[1]/l)
        i = 1
        line = ""

        for reg in all_registers():

            try:
                r = gdb.parse_and_eval(reg)
                if r.type.code == gdb.TYPE_CODE_VOID:
                    continue

                new_value_type_flag = (r.type.code == gdb.TYPE_CODE_FLAGS)
                new_value = r

            except gdb.MemoryError:
                # If this exception is triggered, it means that the current register
                # is corrupted. Just use the register "raw" value (not eval-ed)
                new_value = get_register_ex( reg )
                new_value_type_flag = False

            except:
                new_value = 0

            old_value = self.old_registers[reg] if reg in self.old_registers else 0x00

            line += "%s  " % (Color.greenify(reg))

            if new_value_type_flag:
                line += "%s " % (new_value)
            else:
                new_value = align_address( long(new_value) )
                old_value = align_address( long(old_value) )

                if new_value == old_value:
                    line += "%s " % format_address(new_value)
                else:
                    line += "%s " % Color.colorify(format_address(new_value), attrs="bold red")

            if (i%nb == 0) :
                print(line)
                line = ""
            i+=1

        if len(line) > 0:
            print(line)

        print("Flags: " + flag_register_to_human())

        return

    def context_stack(self):
        if self.get_setting("show_stack")==False:
            return

        self.context_title("stack")

        show_raw = self.get_setting("show_stack_raw")
        nb_lines = self.get_setting("nb_lines_stack")

        try:
            sp = get_sp()
            if show_raw == True:
                mem = read_memory(sp, 0x10 * nb_lines)
                print( hexdump(mem, base=sp) )
            else:
                gdb.execute("dereference %#x %d" % (sp, nb_lines))

        except gdb.MemoryError:
            err("Cannot read memory from $SP (corrupted stack pointer?)")

        return

    def context_code(self):
        if self.get_setting("show_code")==False:
            return

        nb_insn = self.get_setting("nb_lines_code")
        use_capstone = self.has_setting("use_capstone") and self.get_setting("use_capstone")
        pc = get_pc()

        arch = get_arch().lower()
        if is_arm_thumb():
            arch += ":thumb"
            pc   += 1

        self.context_title("code:{}".format(arch))

        try:
            if use_capstone:
                CapstoneDisassembleCommand.disassemble(pc, nb_insn)
                return

            lines = gef_disassemble(pc, nb_insn)
            for addr, content in lines:
                insn = "%#x %s" % (addr, content)
                line = []
                if addr < pc:
                    line+= Color.grayify("%#x\t%s" % (addr, content,) )
                elif addr == pc:
                    line+= Color.colorify("%#x\t%s\t\t%s $pc" % (addr, content, left_arrow), attrs="bold red")

                    if is_conditional_branch(insn):
                        is_taken, reason = is_branch_taken(insn)
                        reason = "[%s]" % reason if reason else ""
                        if is_taken:
                            line+= Color.colorify("\tTAKEN %s" % reason, attrs="bold green")
                        else:
                            line+= Color.colorify("\tNOT taken %s" % reason, attrs="bold red")

                else:
                    line+= "%#x\t%s" % (addr, content)

                print(u"".join(line))

        except gdb.MemoryError:
            err("Cannot disassemble from $PC")
        return

    def context_source(self):
        try:
            pc = get_pc()
            symtabline = gdb.find_pc_line(pc)
            symtab = symtabline.symtab
            line_num = symtabline.line - 1     # we substract one because line number returned by gdb start at 1
            if not symtab.is_valid():
                return

            fpath = symtab.fullname()
            with open(fpath, 'r') as f:
                lines = [l.rstrip() for l in f.readlines()]

        except Exception as e:
            # err("in `context_source, exception '%s' raised: %s" % (e.__class__.__name__, e.message))
            return

        nb_line = self.get_setting("nb_lines_code")
        title = "source:{0:s}+{1:d}".format(symtab.filename, line_num+1)
        self.context_title(title)

        for i in range(line_num-nb_line+1, line_num+nb_line):
            if i < 0:
                continue

            if i < line_num:
                print(Color.grayify("%4d\t %s" % (i+1, lines[i],) ))

            if i==line_num:
                extra_info = self.get_pc_context_info(pc, lines[i])
                print(Color.colorify("%4d\t %s \t\t %s $pc\t" % (i+1, lines[i], left_arrow,), attrs="bold red") + extra_info)

            if i > line_num:
                try:
                    print("%4d\t %s" % (i+1, lines[i],) )
                except IndexError:
                    break
        return

    def get_pc_context_info(self, pc, line):
        try:
            current_block = gdb.block_for_pc(pc)
            if not current_block.is_valid(): return ""
            m = []
            for sym in current_block:
                if not sym.is_function and sym.name in line:
                    key = sym.name
                    val = gdb.parse_and_eval(sym.name)
                    if val.type.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                        addr = long(val.address)
                        addrs = DereferenceCommand.dereference_from(addr)
                        if len(addrs) > 2:
                            addrs = [addrs[0], "[...]", addrs[-1]]

                        f = " " + right_arrow + " "
                        val = f.join(addrs)
                    elif val.type.code == gdb.TYPE_CODE_INT:
                        val = hex(long(val))
                    else:
                        continue

                    found = False
                    for (k,v) in m:
                        if k==key: found = True

                    if not found:
                        m.append( (key, val) )

            if len(m) > 0:
                return "; "+ ", ".join([ "%s=%s"%(Color.yellowify(a),b) for a,b in m ])
        except Exception as e:
            pass
        return ""

    def context_trace(self):
        if self.get_setting("show_trace")==False:
            return

        self.context_title("trace")

        try:
            gdb.execute("backtrace %d" % self.get_setting("nb_lines_backtrace"))
        except gdb.MemoryError:
            err("Cannot backtrace (corrupted frames?)")
        return

    def update_registers(self):
        for reg in all_registers():
            try:
                self.old_registers[reg] = get_register_ex(reg)
            except:
                self.old_registers[reg] = 0
        return


def disable_context():
    __config__["context.enable"] = (False, bool)
    return


def enable_context():
    __config__["context.enable"] = (True, bool)
    return


class HexdumpCommand(GenericCommand):
    """Display arranged hexdump (according to architecture endianness) of memory range."""

    _cmdline_ = "hexdump"
    _syntax_  = "%s (qword|dword|word|byte) LOCATION L[SIZE] [UP|DOWN]" % _cmdline_


    def do_invoke(self, argv):
        self.usage()
        return

    @if_gdb_running
    def _invoke(self, fmt, argv):
        argc = len(argv)
        if argc < 1:
            self.usage()
            return

        read_from = align_address( long(gdb.parse_and_eval(argv[0])) )
        read_len = 10
        up_to_down = True

        if argc >= 2:
            for arg in argv[1:]:
                if arg.startswith("L") or arg.startswith("l"):
                    if arg[1:].isdigit():
                        read_len = long(arg[1:])
                        continue

                if arg in ("UP", "Up", "up"):
                    up_to_down = True
                    continue

                if arg in ("DOWN", "Down", "down"):
                    up_to_down = False
                    continue

        if fmt == "x":
            mem = read_memory(read_from, read_len)
            lines = hexdump(mem, base=read_from).split("\n")
        else:
            lines = self._hexdump(read_from, read_len, fmt)

        if not up_to_down:
            lines.reverse()

        print("\n".join(lines))
        return


    def _hexdump(self, start_addr, length, arrange_as):
        elf = get_elf_headers()
        if elf is None:
            return
        endianness = "<" if elf.e_endianness == 0x01 else ">"
        i = 0

        formats = { 'q': ('Q', 8),
                    'd': ('I', 4),
                    'w': ('H', 2),
        }
        r, l = formats[arrange_as]
        fmt_str = "%#x+%.4x "+vertical_line+" %#."+str(l*2)+"x"
        fmt_pack = endianness + r
        lines = []

        while i < length:
            cur_addr = start_addr + i*l
            mem = read_memory(cur_addr, l)
            val = struct.unpack(fmt_pack, mem)[0]
            lines.append(fmt_str % (start_addr, i*l, val))
            i += 1

        return lines

class HexdumpQwordCommand(HexdumpCommand):
    """
    Display location as QWORD
    """
    _cmdline_ = "hexdump qword"
    _syntax_  = "%s LOCATION L[SIZE] [UP|DOWN]" % _cmdline_
    _aliases_ = ["dq",]

    def do_invoke(self, argv):
        self._invoke("q", argv)
        return

class HexdumpDwordCommand(HexdumpCommand):
    """
    Display location as DWORD
    """
    _cmdline_ = "hexdump dword"
    _syntax_  = "%s LOCATION L[SIZE] [UP|DOWN]" % _cmdline_
    _aliases_ = ["dd",]

    def do_invoke(self, argv):
        self._invoke("d", argv)
        return


class HexdumpWordCommand(HexdumpCommand):
    """
    Display location as WORD
    """
    _cmdline_ = "hexdump word"
    _syntax_  = "%s LOCATION L[SIZE] [UP|DOWN]" % _cmdline_
    _aliases_ = ["dw",]

    def do_invoke(self, argv):
        self._invoke("w", argv)
        return


class HexdumpByteCommand(HexdumpCommand):
    """
    Display location as bytes
    """
    _cmdline_ = "hexdump byte"
    _syntax_  = "%s LOCATION L[SIZE] [UP|DOWN]" % _cmdline_
    _aliases_ = ["dc",]

    def do_invoke(self, argv):
        self._invoke("x", argv)
        return



class DereferenceCommand(GenericCommand):
    """Dereference recursively an address and display information"""

    _cmdline_ = "dereference"
    _syntax_  = "%s [LOCATION] [NB]" % _cmdline_
    _aliases_ = ["telescope", ]


    def __init__(self):
        super(DereferenceCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_recursion", 10)
        return


    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv) < 1:
            err("Missing location.")
            return

        memalign = get_memory_alignment(to_byte=True)
        offset = 0
        regs = [(k, get_register_ex(k)) for k in all_registers()]

        def _pprint_dereferenced(addr, off):
            offset = off * memalign
            current_address = align_address( addr + offset )
            addrs = DereferenceCommand.dereference_from(current_address)
            sep = " %s " % right_arrow
            l  = Color.colorify(format_address(long(addrs[0], 16)), attrs="bold blue")
            l += vertical_line + "+%#.4x: " % offset
            l += sep.join(addrs[1:])
            values = []
            for regname, regvalue in regs:
                if current_address == regvalue:
                    values.append(regname.strip())

            if len(values)>0:
                l += Color.colorify("\t\t"+ left_arrow + ', '.join(values), attrs="bold green")

            offset += memalign
            return l

        nb = int(argv[1]) if len(argv)==2 and argv[1].isdigit() else 1
        start_address = align_address( long(gdb.parse_and_eval(argv[0])) )
        for i in range(0, nb):
            line = _pprint_dereferenced(start_address, i)
            print(line)
        return


    @staticmethod
    def dereference_from(addr):
        prev_addr_value = None
        max_recursion = max(int(__config__["dereference.max_recursion"][0]), 1)
        value = align_address( long(addr) )
        addr  = lookup_address( value )

        if addr is None:
            return [ format_address(value), ]

        msg = []

        while max_recursion:

            if addr.value == prev_addr_value:
                msg.append( "[loop detected]")
                break

            msg.append( format_address(addr.value) )

            prev_addr_value = addr.value
            max_recursion -= 1

            # can we derefence more ?
            deref = addr.dereference()
            new_addr = lookup_address(deref)
            if new_addr is not None:
                addr = new_addr
                continue

            # otherwise try to parse the value
            if addr.section:
                if addr.section.is_executable() and addr.is_in_text_segment():
                    cmd = gdb.execute("x/i %#x" % addr.value, to_string=True).replace("=>", '')
                    cmd = re.sub('\s+',' ', cmd.strip()).split(" ", 1)[1]
                    msg.append( "%s" % Color.redify(cmd) )
                    break

                elif addr.section.permission.value & Permission.READ:
                    if is_readable_string(addr.value):
                        s = read_cstring_from_memory(addr.value)
                        if len(s) < get_memory_alignment(to_byte=True):
                            txt = "%s (\"%s\"?)" %  (format_address(deref), Color.greenify(s))
                        elif len(s) >= 50:
                            txt = Color.greenify('"%s[...]"' % s[:50])
                        else:
                            txt = Color.greenify('"%s"' % s)

                        msg.append( txt )
                        break

            # if not able to parse cleanly, simply display and break
            msg.append( "%#x" % ( long(deref) & 0xffffffffffffffff ))
            break


        return msg



class ASLRCommand(GenericCommand):
    """View/modify GDB ASLR behavior."""

    _cmdline_ = "aslr"
    _syntax_  = "%s (on|off)" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            ret = gdb.execute("show disable-randomization", to_string=True)
            i = ret.find("virtual address space is ")
            if i < 0:
                return

            msg = "ASLR is currently "
            if ret[i+25:].strip() == "on.":
                msg+= Color.redify( "disabled" )
            else:
                msg+= Color.greenify( "enabled" )

            print("%s" % msg)

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



class ResetCacheCommand(GenericCommand):
    """Reset cache of all stored data."""

    _cmdline_ = "reset-cache"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        reset_all_caches()
        return



class VMMapCommand(GenericCommand):
    """Display virtual memory mapping"""

    _cmdline_ = "vmmap"
    _syntax_  = "%s" % _cmdline_

    @if_gdb_running
    def do_invoke(self, argv):
        vmmap = get_process_maps()
        if vmmap is None or len(vmmap)==0:
            err("No address mapping information found")
            return

        if is_elf64():
            print("%18s %18s %18s %4s %s" % ("Start", "End", "Offset", "Perm", "Path"))
        else:
            print("%10s %10s %10s %4s %s" % ("Start", "End", "Offset", "Perm", "Path"))
        for entry in vmmap:
            l = []
            l.append( format_address( entry.page_start ))
            l.append( format_address( entry.page_end ))
            l.append( format_address( entry.offset ))

            if entry.permission.value == (Permission.READ|Permission.WRITE|Permission.EXECUTE) :
                l.append(Color.colorify(str(entry.permission), attrs="blink bold red"))
            else:
                l.append(str(entry.permission))

            l.append( entry.path )

            print(" ".join(l))
        return


class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary (Truth is out there)."""

    _cmdline_ = "xfiles"
    _syntax_  = "%s [name]" % _cmdline_

    @if_gdb_running
    def do_invoke(self, args):
        name = None if len(args)==0 else args[0]
        formats = {"Start": "{:{align}20s}",
                   "End":   "{:{align}20s}",
                   "Name":  "{:{align}30s}",
                   "File":  "{:s}",
                  }
        args = ("Start", "End", "Name", "File")
        f = " ".join([formats[k] for k in args])
        print(f.format(*args, align="^"))

        for xfile in get_info_files():
            if name is not None and xfile.name != name:
                continue

            l= ""
            l+= formats["Start"].format(format_address(xfile.zone_start), align=">")
            l+= formats["End"].format(format_address(xfile.zone_end), align=">")
            l+= formats["Name"].format(xfile.name, align="^")
            l+= formats["File"].format(xfile.filename, align="<")
            print(l)
        return


class XAddressInfoCommand(GenericCommand):
    """Get virtual section information for specific address"""

    _cmdline_ = "xinfo"
    _syntax_  = "%s LOCATION" % _cmdline_


    def __init__(self):
        super(XAddressInfoCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @if_gdb_running
    def do_invoke (self, argv):
        if len(argv) < 1:
            err ("At least one valid address must be specified")
            return

        for sym in argv:
            try:
                addr = align_address( parse_address(sym) )
                print(titlify("xinfo: %#x" % addr ))
                self.infos(addr)

            except gdb.error as gdb_err:
                err("%s" % gdb_err)

        return


    def infos(self, address):
        addr = lookup_address(address)
        if addr is None:
            warn("Cannot reach %#x in memory space" % address)
            return

        sect = addr.section
        info = addr.info

        if sect:
            print("Found %s" % format_address(addr.value))
            print("Page: %s %s %s (size=%#x)" % (format_address(sect.page_start),
                                                  right_arrow,
                                                  format_address(sect.page_end),
                                                  sect.page_end-sect.page_start))
            print("Permissions: %s" % sect.permission)
            print("Pathname: %s" % sect.path)
            print("Offset (from page): +%#x" % (addr.value-sect.page_start))
            print("Inode: %s" % sect.inode)

        if info:
            print("Segment: %s (%s-%s)" % (info.name,
                                            format_address(info.zone_start),
                                            format_address(info.zone_end)))

        return


class XorMemoryCommand(GenericCommand):
    """XOR a block of memory."""

    _cmdline_ = "xor-memory"
    _syntax_  = "%s (display|patch) <address> <size_to_read> <xor_key> " % _cmdline_


    def do_invoke(self, argv):
        if len(argv) == 0:
            err("Missing subcommand (display|patch)")
            self.usage()
        return

class XorMemoryDisplayCommand(GenericCommand):
    """Display a block of memory by XOR-ing each key with a key."""

    _cmdline_ = "xor-memory display"
    _syntax_  = "%s <address> <size_to_read> <xor_key> [-i]" % _cmdline_

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv) not in (3, 4):
            self.usage()
            return

        address = long(gdb.parse_and_eval(argv[0]))
        length = long(argv[1])
        key = argv[2]
        show_as_instructions = True if len(argv)==4 and argv[3]=="-i" else False
        block = read_memory(address, length)
        info("Displaying XOR-ing %#x-%#x with %s" % (address, address+len(block), repr(key)))

        print( titlify("Original block") )
        if show_as_instructions:
            CapstoneDisassembleCommand.disassemble(address, -1, code=block)
        else:
            print( hexdump(block, base=address) )


        print( titlify("XOR-ed block") )
        xored = XOR(block, key)
        if show_as_instructions:
            CapstoneDisassembleCommand.disassemble(address, -1, code=xored)
        else:
            print( hexdump(xored, base=address))
        return


class XorMemoryPatchCommand(GenericCommand):
    """Patch a block of memory by XOR-ing each key with a key."""

    _cmdline_ = "xor-memory patch"
    _syntax_  = "%s <address> <size_to_read> <xor_key>" % _cmdline_

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = parse_address( argv[0] )
        length, key = long(argv[1]), argv[2]
        block = read_memory(address, length)
        info("Patching XOR-ing %#x-%#x with '%s'" % (address, address+len(block), key))

        xored_block = XOR(block, key)
        write_memory(address, xored_block, length)
        return


class TraceRunCommand(GenericCommand):
    """Create a runtime trace of all instructions executed from $pc to LOCATION specified."""

    _cmdline_ = "trace-run"
    _syntax_  = "%s LOCATION [MAX_CALL_DEPTH]" % _cmdline_


    def __init__(self):
        super(TraceRunCommand, self).__init__(self._cmdline_, complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_tracing_recursion", 1)
        self.add_setting("tracefile_prefix", "./gef-trace-")
        return

    @if_gdb_running
    def do_invoke(self, argv):
        if len(argv) not in (1, 2):
            self.usage()
            return

        if len(argv)==2 and argv[1].isdigit():
            depth = long(argv[1])
        else:
            depth = 1

        try:
            loc_start   = get_pc()
            loc_end     = long(gdb.parse_and_eval(argv[0]))
        except gdb.error as e:
            err("Invalid location: %s" % e)
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
        info("Tracing from %#x to %#x (max depth=%d)" % (loc_start, loc_end,depth))
        logfile = "%s%#x-%#x.txt" % (self.get_setting("tracefile_prefix"), loc_start, loc_end)

        disable_output(to_file=logfile)
        disable_context()

        self._do_trace(loc_start, loc_end, depth)

        enable_context()
        enable_output()

        ok("Done, logfile stored as '%s'" % logfile)
        info("Hint: import logfile with `ida_color_gdb_trace.py` script in IDA to visualize path")
        return


    def _do_trace(self, loc_start, loc_end, depth):
        loc_old = 0
        loc_cur = loc_start
        frame_count_init = self.get_frames_size()

        print("#")
        print("# Execution tracing of %s" % get_filepath())
        print("# Start address: %s" % format_address(loc_start))
        print("# End address: %s" % format_address(loc_end))
        print("# Recursion level: %d" % depth)
        print("# automatically generated by gef.py")
        print("#\n")

        while loc_cur != loc_end:
            try:
                delta = self.get_frames_size() - frame_count_init

                if delta <= depth :
                    gdb.execute( "stepi" )
                else:
                    gdb.execute( "finish" )

                loc_cur = get_pc()
                gdb.flush()

            except Exception as e:
                print("#")
                print("# Execution interrupted at address %s" % format_address(loc_cur))
                print("# Exception: %s" % e)
                print("#\n")
                break

        return



class PatternCommand(GenericCommand):
    """This command will create or search a De Bruijn cyclic pattern to facilitate determining the offset in
    memory. The algorithm used is the same as the one used by pwntools, and can therefore be used in conjunction."""

    _cmdline_ = "pattern"
    _syntax_  = "%s (create|search) <args>" % _cmdline_

    def __init__(self, *args, **kwargs):
        super(PatternCommand, self).__init__()
        self.add_setting("length", 1024)
        return

    def do_invoke(self, argv):
        self.usage()
        return


class PatternCreateCommand(GenericCommand):
    """Cyclic pattern generation"""

    _cmdline_ = "pattern create"
    _syntax_  = "%s [SIZE]" % _cmdline_


    def do_invoke(self, argv):

        if len(argv) == 1:
            if not argv[0].isdigit():
                err("Invalid size")
                return
            __config__["pattern.length"] = (long(argv[0]), long)
        elif len(argv) > 1:
            err("Invalid syntax")
            return

        size = __config__.get("pattern.length", 1024)[0]
        info("Generating a pattern of %d bytes" % size)
        patt = generate_cyclic_pattern(size).decode("utf-8")
        if size < 1024:
            print(patt)

        var_name = gef_convenience('"%s"' % patt)
        ok("Saved as '%s'" % var_name)
        return


class PatternSearchCommand(GenericCommand):
    """Cyclic pattern search"""

    _cmdline_ = "pattern search"
    _syntax_  = "%s PATTERN [SIZE]" % _cmdline_


    def do_invoke(self, argv):
        if len(argv) not in (1, 2):
            self.usage()
            return

        if len(argv)==2:
            if not argv[0].isdigit():
                err("Invalid size")
                return
            size = long(argv[1])
        else:
            size = __config__.get("pattern.length", 1024)[0]

        pattern = argv[0]
        info("Searching '%s'" % pattern)
        self.search(pattern, size)
        return


    def search(self, pattern, size):
        try:
            addr = long( gdb.parse_and_eval(pattern) )
            if get_memory_alignment() == 32:
                pattern_be = struct.pack(">I", addr)
                pattern_le = struct.pack("<I", addr)
            else:
                pattern_be = struct.pack(">Q", addr)
                pattern_le = struct.pack("<Q", addr)
        except gdb.error:
            err("Incorrect pattern")
            return

        buf = generate_cyclic_pattern(size)
        found = False

        off = buf.find(pattern_le)
        if off >= 0:
            ok("Found at offset %d (little-endian search) %s" % (off, Color.colorify("likely", attrs="bold red") if is_little_endian() else ""))
            found = True

        off = buf.find(pattern_be)
        if off >= 0:
            ok("Found at offset %d (big-endian search) %s" % (off, Color.colorify("likely", attrs="bold green") if is_big_endian() else ""))
            found = True

        if not found:
            err("Pattern not found")

        return


class ChecksecCommand(GenericCommand):
    """Checksec.sh (http://www.trapkit.de/tools/checksec.html) port."""

    _cmdline_ = "checksec"
    _syntax_  = "%s (filename)" % _cmdline_

    def __init__(self):
        super(ChecksecCommand, self).__init__(complete=gdb.COMPLETE_FILENAME)
        return


    def pre_load(self):
        try:
            fpath = which("readelf")
            self.add_setting("readelf_path", fpath)
        except IOError as e :
            raise GefMissingDependencyException( str(e) )
        return


    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            if not is_alive():
                warn("No executable/library specified")
                return

            filename = get_filepath()

        elif argc == 1:
            filename = argv[0]

        else:
            self.usage()
            return

        if not os.access(self.get_setting("readelf_path"), os.X_OK):
            err("Could not access readelf")
            return

        info("%s for '%s'" % (self._cmdline_, filename))
        self.checksec(filename)
        return


    def do_check(self, title, opt, filename, pattern, is_match):
        options = opt.split(" ")
        buf   = "%-50s" % (title+":")
        cmd   = [self.get_setting("readelf_path"), ]
        cmd  += options
        cmd  += [filename, ]

        ret = gef_execute_external( cmd )

        lines = ret.split("\n")
        found = False

        for line in lines:
            if re.search(pattern, line):
                buf += Color.GREEN
                if is_match:
                    buf += Color.greenify("Yes")
                else:
                    buf += Color.redify("No")
                found = True
                break

        if not found:
            if is_match:
                buf+= Color.redify("No")
            else:
                buf+= Color.greenify("Yes")

        print("%s" % buf)
        return


    def checksec(self, filename):
        # check for canary
        self.do_check("Canary", "-s", filename, r'__stack_chk_fail', is_match=True)

        # check for NX
        self.do_check("NX Support", "-W -l", filename, r'GNU_STACK.*RWE', is_match=False)

        # check for PIE support
        self.do_check("PIE Support", "-h", filename, r'Type:.*EXEC', is_match=False)
        # todo : add check for (DEBUG) if .so

        # check for RPATH
        self.do_check("No RPATH", "-d -l", filename, r'rpath', is_match=False)

        # check for RUNPATH
        self.do_check("No RUNPATH", "-d -l", filename, r'runpath', is_match=False)

        # check for RELRO
        self.do_check("Partial RelRO", "-l", filename, r'GNU_RELRO', is_match=True)
        self.do_check("Full RelRO", "-d", filename, r'BIND_NOW', is_match=True)

        return



class FormatStringSearchCommand(GenericCommand):
    """Exploitable format-string helper: this command will set up specific breakpoints
    at well-known dangerous functions (printf, snprintf, etc.), and check if the pointer
    holding the format string is writable, and therefore susceptible to format string
    attacks if an attacker can control its content."""
    _cmdline_ = "format-string-helper"
    _syntax_ = "%s" % _cmdline_
    _aliases_ = ["fmtstr-helper",]


    def do_invoke(self, argv):
        dangerous_functions = {
            'printf':     0,
            'sprintf':    1,
            'fprintf':    1,
            'snprintf':   2,
            'vsnprintf':  2,
        }

        disable_output()

        for func_name, num_arg in dangerous_functions.items():
            FormatStringBreakpoint(func_name, num_arg)

        enable_output()
        ok("Enabled %d FormatStringBreakpoint" % len(dangerous_functions.keys()))
        return


class GefCommand(gdb.Command):
    """GEF main command: view all new commands by typing `gef`"""

    _cmdline_ = "gef"
    _syntax_  = "%s (config|help|save|restore|restore)" % _cmdline_

    def __init__(self):
        super(GefCommand, self).__init__(GefCommand._cmdline_,
                                         gdb.COMMAND_SUPPORT,
                                         gdb.COMPLETE_NONE,
                                         True)

        __config__["gef.no_color"] = (False, bool)
        __config__["gef.follow_child"] = (True, bool)

        self.classes = [ResetCacheCommand,
                        XAddressInfoCommand,
                        XorMemoryCommand, XorMemoryDisplayCommand, XorMemoryPatchCommand,
                        FormatStringSearchCommand,
                        TraceRunCommand,
                        PatternCommand, PatternSearchCommand, PatternCreateCommand,
                        ChecksecCommand,
                        VMMapCommand,
                        XFilesCommand,
                        ASLRCommand,
                        DereferenceCommand,
                        HexdumpCommand, HexdumpQwordCommand, HexdumpDwordCommand, HexdumpWordCommand, HexdumpByteCommand,
                        CapstoneDisassembleCommand,
                        ContextCommand,
                        EntryPointBreakCommand,
                        ElfInfoCommand,
                        ProcessListingCommand,
                        AssembleCommand,
                        FileDescriptorCommand,
                        ROPgadgetCommand,
                        RopperCommand,
                        ShellcodeCommand, ShellcodeSearchCommand, ShellcodeGetCommand,
                        DetailRegistersCommand,
                        SolveKernelSymbolCommand,
                        AliasCommand, AliasShowCommand, AliasSetCommand, AliasUnsetCommand, AliasDoCommand,
                        GlibcHeapCommand, GlibcHeapArenaCommand, GlibcHeapChunkCommand, GlibcHeapBinsCommand, GlibcHeapFastbinsYCommand, GlibcHeapUnsortedBinsCommand, GlibcHeapSmallBinsCommand, GlibcHeapLargeBinsCommand,
                        NopCommand,
                        RemoteCommand,
                        UnicornEmulateCommand,
                        ChangePermissionCommand,
                        FlagsCommand,
                        SearchPatternCommand,
                        IdaInteractCommand,
                        ProcessIdCommand,
                        ChangeFdCommand,
                        RetDecCommand,
                        PCustomCommand,

                        # add new commands here
                        # when subcommand, main command must be placed first
                        ]

        self.__cmds = [ (x._cmdline_, x) for x in self.classes ]
        self.__loaded_cmds = []
        self.load()

        # loading GEF sub-commands
        GefHelpCommand(self.__loaded_cmds)
        GefConfigCommand(self.loaded_command_names)
        GefSaveCommand()
        GefRestoreCommand()
        GefMissingCommand()

        if os.access(GEF_RC, os.R_OK):
            gdb.execute("gef restore")

        if __config__.get("gef.follow_child")[0]:
            gdb.execute("set follow-fork-mode child")
        else:
            gdb.execute("set follow-fork-mode parent")
        return


    @property
    def loaded_command_names(self):
        return [ x[0] for x in self.__loaded_cmds ]


    def invoke(self, args, from_tty):
        gdb.execute("gef help")
        return


    def load(self, mod=None):
        """
        Load all the commands defined by GEF into GBD.
        If a configuration file is found, the settings are restored.
        """
        global __loaded__, __missing__

        __loaded__ = []
        __missing__ = {}
        nb_missing = 0

        def is_loaded(x):
            for (n, c, o) in __loaded__:
                if x == n:
                    return True
            return False

        for (cmd, class_name) in self.__cmds:
            try:
                if " " in cmd:
                    # if subcommand, check root command is loaded
                    root = cmd.split(' ', 1)[0]
                    if not is_loaded(root):
                        continue

                __loaded__.append( (cmd, class_name, class_name())  )

                if hasattr(class_name, "_aliases_"):
                    aliases = getattr(class_name, "_aliases_")
                    for alias in aliases:
                        gdb.execute("alias -a {} = {}".format(alias, cmd, ))

            except Exception as reason:
                __missing__[cmd] = reason
                nb_missing += 1

        self.__loaded_cmds = sorted(__loaded__, key=lambda x: x[1]._cmdline_)

        print("%s ready, type `%s' to start, `%s' to configure" % (Color.greenify("GEF"),
                                                                   Color.colorify("gef",attrs="underline yellow"),
                                                                   Color.colorify("gef config", attrs="underline pink")))

        ver = "%d.%d" % (sys.version_info.major, sys.version_info.minor)
        nb_cmds = len(__loaded__)
        print("%s commands loaded, using Python engine %s" % (Color.colorify(str(nb_cmds), attrs="bold green"),
                                                              Color.colorify(ver, attrs="bold red")))

        if nb_missing > 0:
            warn("%s commands could not be loaded, run `%s` to know why."%(Color.colorify(str(nb_missing), attrs="bold red"),
                                                                           Color.colorify("gef missing", attrs="underline pink")))

        return

class GefHelpCommand(gdb.Command):
    """GEF help sub-command."""
    _cmdline_ = "gef help"
    _syntax_  = "%s" % _cmdline_

    def __init__(self, commands, *args, **kwargs):
        super(GefHelpCommand, self).__init__(GefHelpCommand._cmdline_,
                                             gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_NONE,
                                             False)
        self.__doc__ = self.generate_help(commands)
        return

    def invoke(self, args, from_tty):
        print("Syntax: %s\n" % self._syntax_)
        print(self.__doc__)
        return

    def generate_help(self, commands):
        d = []
        d.append( titlify("GEF - GDB Enhanced Features") )

        for (cmd, class_name, obj) in commands:
            if " " in cmd:
                # do not print out subcommands in main help
                continue

            doc = class_name.__doc__ if hasattr(class_name, "__doc__") else ""
            doc = "\n                         ".join(doc.split("\n"))

            if hasattr(class_name, "_aliases_"):
                aliases = ", ".join(class_name._aliases_)
                aliases = "(alias: %s)" % aliases
            else:
                aliases = ""

            msg = "%-25s -- %s %s" % (cmd, Color.greenify(doc), aliases)

            d.append( msg )
        return "\n".join(d)

class GefConfigCommand(gdb.Command):
    """GEF configuration sub-command
    This command will help set/view GEF settingsfor the current debugging session.
    It is possible to make those changes permanent by running `gef save` (refer
    to this command help), and/or restore previously saved settings by running
    `gef restore` (refer help).
    """
    _cmdline_ = "gef config"
    _syntax_  = "%s [debug_on|debug_off][setting_name] [setting_value]" % _cmdline_

    def __init__(self, loaded_commands, *args, **kwargs):
        super(GefConfigCommand, self).__init__(GefConfigCommand._cmdline_,
                                               gdb.COMMAND_SUPPORT,
                                               gdb.COMPLETE_NONE,
                                               False)
        self.loaded_commands = loaded_commands
        return

    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        argc = len(argv)

        if not (0 <= argc <= 2):
            err("Invalid number of arguments")
            return

        if argc==1 and args[0]=="debug_on":
            enable_debug()
            info("Enabled debug mode")
            return

        if argc==1 and args[0]=="debug_off":
            disable_debug()
            info("Disabled debug mode")
            return

        if argc==0 or argc==1:
            self.print_settings(argc, argv)
            return

        self.set_setting(argc, argv)
        return

    def print_settings(self, argc, argv):
        config_items = sorted( __config__ )
        plugin_name = argv[0] if argc==1 and argv[0] in self.loaded_commands else ""
        print( titlify("GEF configuration settings %s" % plugin_name) )
        for key in config_items:
            if plugin_name not in key: continue
            value, type = __config__.get(key, None)
            print("%-40s  (%s) = %s" % (key, type.__name__, value))
        return

    def set_setting(self, argc, argv):
        if "." not in argv[0]:
            err("Invalid command format")
            return

        plugin_name, setting_name = argv[0].split(".", 1)

        if plugin_name not in self.loaded_commands + ["gef",]:
            err("Unknown plugin '%s'" % plugin_name)
            return

        _curval, _type = __config__.get( argv[0], (None, None) )
        if _type == None:
            err("Failed to get '%s' config setting" % (argv[0], ))
            return

        try:
            if _type == bool:
                _newval = True if argv[1] in ("True", "TRUE", "true", "1") else False
            else:
                _newval = argv[1]
                _type( _newval )

        except:
            err("%s expects type '%s'" % (argv[0], _type.__name__))
            return

        __config__[ argv[0] ] = (_newval, _type)
        return

class GefSaveCommand(gdb.Command):
    """GEF save sub-command
    Saves the current configuration of GEF to disk (by default in file '~/.gef.rc')
    """
    _cmdline_ = "gef save"
    _syntax_  = "%s" % _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefSaveCommand, self).__init__(GefSaveCommand._cmdline_,
                                             gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_NONE,
                                             False)
        return

    def invoke(self, args, from_tty):
        cfg = configparser.RawConfigParser()
        old_sect = None
        for key in sorted( __config__.keys() ):
            sect, optname = key.split(".", 1)
            value, type = __config__.get(key, None)

            if old_sect != sect:
                cfg.add_section(sect)
                old_sect = sect

            cfg.set(sect, optname, value)

        with open(GEF_RC, "w") as fd:
            cfg.write(fd)

        ok("Configuration saved to '%s'" % GEF_RC)
        return

class GefRestoreCommand(gdb.Command):
    """GEF restore sub-command
    Loads settings from file '~/.gef.rc' and apply them to the configuration of GEF
    """
    _cmdline_ = "gef restore"
    _syntax_  = "%s" % _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefRestoreCommand, self).__init__(GefRestoreCommand._cmdline_,
                                                gdb.COMMAND_SUPPORT,
                                                gdb.COMPLETE_NONE,
                                                False)
        return

    def invoke(self, args, from_tty):
        cfg = configparser.ConfigParser()
        cfg.read(GEF_RC)

        if cfg.sections() is None or len(cfg.sections())==0:
            return

        for section in cfg.sections():
            for optname in cfg.options(section):
                try:
                    key = "%s.%s" % (section, optname)
                    old_value, _type = __config__.get(key)
                    new_value = cfg.get(section, optname)
                    if _type == bool:
                        new_value = True if new_value=='True' else False
                    else:
                        new_value = _type(new_value)
                    __config__[key] = (new_value, _type)
                except:
                    warn("Could not restore '%s'" % key)

        ok("Configuration from '%s' restored" % GEF_RC)
        return

class GefMissingCommand(gdb.Command):
    """GEF missing sub-command
    Display the GEF commands that could not be loaded, along with the reason of why
    they could not be loaded.
    """
    _cmdline_ = "gef missing"
    _syntax_  = "%s" % _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefMissingCommand, self).__init__(GefMissingCommand._cmdline_,
                                                gdb.COMMAND_SUPPORT,
                                                gdb.COMPLETE_NONE,
                                                False)
        return

    def invoke(self, args, from_tty):
        global __missing__

        missing_commands = __missing__.keys()
        if len(missing_commands)==0:
            ok("No missing command")
            return

        for missing_command in missing_commands:
            reason = __missing__[missing_command]
            warn("Command `{}` is missing, reason {} {}".format(missing_command, right_arrow, reason))
        return


def __gef_prompt__(current_prompt):
    prompt = "gef> " if PYTHON_MAJOR == 2 else "gef\u27a4  "
    if is_alive():
        fmt_prompt = "\001\033[1;32m\002{0:s}\001\033[0m\002".format(prompt)
    else:
        fmt_prompt = "\001\033[1;31m\002{0:s}\001\033[0m\002".format(prompt)
    return fmt_prompt


if __name__  == "__main__":

    # setup prompt
    gdb.prompt_hook = __gef_prompt__

    # setup config
    gdb.execute("set confirm off")
    gdb.execute("set verbose off")
    gdb.execute("set height 0"),
    gdb.execute("set width 0")

    # gdb history
    gdb.execute("set history filename ~/.gdb_history")
    gdb.execute("set history save")

    # aliases
    # WinDBG-like aliases (I like them)

    # breakpoints
    gdb.execute("alias -a bl = info breakpoints")
    gdb.execute("alias -a bp = break")
    gdb.execute("alias -a be = enable breakpoints")
    gdb.execute("alias -a bd = disable breakpoints")
    gdb.execute("alias -a bc = delete breakpoints")
    gdb.execute("alias -a tbp = tbreak")
    gdb.execute("alias -a tba = thbreak")
    gdb.execute("alias -a ptc = finish")

    # runtime
    gdb.execute("alias -a g = continue")

    # memory access
    gdb.execute("alias -a uf = disassemble")

    # context
    gdb.execute("alias -a argv = show args")
    gdb.execute("alias -a kp = info stack")

    try:
        # this will raise a gdb.error unless we're on x86
        # we can safely ignore this
        gdb.execute("set disassembly-flavor intel")
    except gdb.error:
        pass

    # SIGALRM will simply display a message, but gdb won't forward the signal to the process
    gdb.execute("handle SIGALRM print nopass")

    # load GEF
    GefCommand()

    # gdb events configuration
    gdb.events.stop.connect(hook_stop_handler)
    gdb.events.new_objfile.connect(new_objfile_handler)
    gdb.events.exited.connect(exit_handler)
