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
# Tested on
# * x86-32/x86-64 (even though you should totally use `gdb-peda` (https://github.com/longld/peda) instead)
# * arm (32b)
# * aarch64/armv8 (64b)
# * mips
# * powerpc32/powerpc64
# * sparc/sparc64 (v8+)
#
#
# Tested on gdb 7.x / python 2.6 & 2.7 & 3.x
#
# To start: in gdb, type `source /path/to/gef.py`
#
#
#

from __future__ import print_function

import math
import struct
import subprocess
import functools
import sys
import re
import tempfile
import os
import binascii
import getopt
import traceback
import threading
import collections
import time
import resource
import string
import itertools
import hashlib
import shutil
import socket


if sys.version_info.major == 2:
    from HTMLParser import HTMLParser
    from cStringIO import StringIO
    from urllib import urlopen
    import ConfigParser as configparser
    import xmlrpclib

    # Compat Py2/3 hacks
    range = xrange

    PYTHON_MAJOR = 2

elif sys.version_info.major == 3:
    from html.parser import HTMLParser
    from io import StringIO
    from urllib.request import urlopen
    import configparser
    import xmlrpc.client as xmlrpclib

    # Compat Py2/3 hack
    long = int
    unicode = str
    FileNotFoundError = IOError

    PYTHON_MAJOR = 3

else:
    raise Exception("WTF is this Python version??")


def __update_gef(argv):
    gef_local = os.path.realpath(argv[0])
    hash_gef_local = hashlib.sha256( open(gef_local).read() ).hexdigest()
    gef_remote = "https://raw.githubusercontent.com/hugsy/gef/master/gef.py"
    fd, fpath = tempfile.mkstemp()
    http = urlopen(gef_remote)
    if http.getcode() != 200:
        print("[-] Failed to update")
        return

    with os.fdopen(fd, "w") as f:
        f.write( http.read() )

    hash_gef_remote = hashlib.sha256( open(fpath).read() ).hexdigest()

    if hash_gef_local==hash_gef_remote:
        print("No update")
    else:
        shutil.copyfile(fpath, gef_local)
        print("Updated")
    os.unlink(fpath)
    return


try:
    import gdb
    ALLOW_UPDATE_ONLY = False
except ImportError:
    ALLOW_UPDATE_ONLY = True
    if len(sys.argv)!=2 or sys.argv[1]!="--update":
        sys.exit(1)
    sys.exit( __update_gef(sys.argv) )



__aliases__ = {}
__config__ = {}
__infos_files__ = []
__loaded__ = []
NO_COLOR = False
DEFAULT_PAGE_ALIGN_SHIFT = 12
DEFAULT_PAGE_SIZE = 1 << DEFAULT_PAGE_ALIGN_SHIFT
GEF_RC = os.getenv("HOME") + "/.gef.rc"

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

class GefNoDebugInformation(GefGenericException):
    pass


# https://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
class memoize(object):
    """Custom Memoize class with resettable cache"""

    def __init__(self, func):
        self.func = func
        self.is_memoized = True
        self.cache = {}
        return

    def __call__(self, *args):
        if args not in self.cache:
            value = self.func(*args)
            self.cache[args] = value
            return value
        return self.func(*args)

    def __repr__(self):
        return self.func.__doc__

    def __get__(self, obj, objtype):
        fn = functools.partial(self.__call__, obj)
        fn.reset = self._reset
        return fn

    def reset(self):
        self.cache = {}
        return


def reset_all_caches():
    for s in dir(sys.modules['__main__']):
        o = getattr(sys.modules['__main__'], s)
        if hasattr(o, "is_memoized") and o.is_memoized:
            o.reset()
    return


# let's get fancy
class Color:
    NORMAL         = "\x1b[0m"
    GRAY           = "\x1b[30m"
    RED            = "\x1b[31m"
    GREEN          = "\x1b[32m"
    YELLOW         = "\x1b[33m"
    BLUE           = "\x1b[34m"
    PINK           = "\x1b[35m"
    BOLD           = "\x1b[1m"
    UNDERLINE_ON   = "\x1b[4m"
    UNDERLINE_OFF  = "\x1b[24m"
    ITALIC_ON      = "\x1b[3m"
    ITALIC_OFF     = "\x1b[23m"
    CLEAR_LINE     = "\x1b[1K"

    @staticmethod
    def redify(msg):     return Color.RED + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def greenify(msg):   return Color.GREEN + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def blueify(msg):    return Color.BLUE + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def yellowify(msg):  return Color.YELLOW + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def grayify(msg):    return Color.GRAY + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def pinkify(msg):    return Color.PINK + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def boldify(msg):    return Color.BOLD + msg + Color.NORMAL if not NO_COLOR else msg
    @staticmethod
    def underlinify(msg):return Color.UNDERLINE_ON + msg + Color.UNDERLINE_OFF if not NO_COLOR else msg
    @staticmethod
    def italicify(msg):  return Color.ITALC_ON + msg + Color.ITALIC_OFF if not NO_COLOR else msg


def left_arrow():
    return "\u2190" if PYTHON_MAJOR == 3 else "<-"

def right_arrow():
    return "\u2192" if PYTHON_MAJOR == 3 else "->"

def horizontal_line():
    return "\u2500" if PYTHON_MAJOR == 3 else "-"

def vertical_line():
    return "\u2502" if PYTHON_MAJOR == 3 else "|"


# helpers
class Address:
    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
        self.section = kwargs.get("section", None)
        self.info = kwargs.get("info", None)
        return

    def __str__(self):
        return hex( self.value )


class Permission:
    NONE      = 0
    READ      = 1
    WRITE     = 2
    EXECUTE   = 4
    ALL       = 7

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
    """
    def __init__(self, addr=None):
        # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671
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
        return GlibcChunk(addr)

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

    def __str__(self):
        top    = self.deref_as_long(self.top)
        nfree  = self.deref_as_long(self.next_free)
        sysmem = long(self.system_mem)
        m = "Arena ("
        m+= "base={:#x},".format(self.__addr)
        m+= "top={:#x},".format(top)
        m+= "next_free={:#x},".format(nfree)
        m+= "system_mem={:#x}".format(sysmem)
        m+= ")"
        return m


class GlibcChunk:
    """
    Glibc chunk class
    """
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
        cursz = self.get_chunk_size()
        if cursz == 0x00: return cursz
        return cursz - 2*self.arch


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


    #
    # Best Glibc heap write-up:
    # https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
    #
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
    return "{0}[ {1}{2}{3}{4} ]{0}".format(horizontal_line()*n, Color.BOLD, color, msg, Color.NORMAL)

def err(msg):
    gdb.write(Color.BOLD+Color.RED+"[!]"+Color.NORMAL+" "+msg+"\n", gdb.STDERR)
    gdb.flush()
    return

def warn(msg):
    gdb.write(Color.BOLD+Color.YELLOW+"[*]"+Color.NORMAL+" "+msg+"\n", gdb.STDLOG)
    gdb.flush()
    return

def ok(msg):
    gdb.write(Color.BOLD+Color.GREEN+"[+]"+Color.NORMAL+" "+msg+"\n", gdb.STDLOG)
    gdb.flush()
    return

def info(msg):
    gdb.write(Color.BOLD+Color.BLUE+"[+]"+Color.NORMAL+" "+msg+"\n", gdb.STDLOG)
    gdb.flush()
    return

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
    patt = re.compile(r'^(0x[0-9a-f]{,16})(.*)$', flags=re.IGNORECASE)
    for line in lines:
        parts = [ x for x in re.split(patt, line) if len(x)>0 ]
        addr = int(parts[0], 16)
        code = parts[1].strip()
        result.append( (addr, code) )
    return result


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
    reg = arm_flag_register()
    if not val:
        val = get_register_ex( reg )
    return flags_to_human(val, arm_flags_table())


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


######################[ Intel x86-32 specific ]######################
@memoize
def x86_32_registers():
    return [ "$eax   ", "$ebx   ", "$ecx   ", "$edx   ", "$esp   ", "$ebp   ", "$esi   ",
             "$edi   ", "$eip   ", "$cs    ", "$ss    ", "$ds    ", "$es    ",
             "$fs    ", "$gs    ", "$eflags", ]

@memoize
def x86_32_return_register():
    return "$eax"


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
              8: "less",
              9: "greater",
              10: "equal",
              11: "overflow",
    }
    return table

def powerpc_flags_to_human(val=None):
    # http://www.csit-sun.pub.ro/~cpop/Documentatie_SM/Motorola_PowerPC/PowerPc/GenInfo/pemch2.pdf
    reg = powerpc_flag_register()
    if not val:
        val = get_register_ex( reg )
    return flags_to_human(val, powerpc_flags_table())


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


def write_memory(address, buffer, length=0x10):
    if PYTHON_MAJOR == 2: buffer = str(buffer)
    return gdb.selected_inferior().write_memory(address, buffer, length)


def read_memory(addr, length=0x10):
    if PYTHON_MAJOR == 2:
        return gdb.selected_inferior().read_memory(addr, length)
    else:
        return gdb.selected_inferior().read_memory(addr, length).tobytes()


def read_int_from_memory(addr):
    arch = get_memory_alignment()/8
    mem = read_memory( addr, arch)
    fmt = endian_str()+"I" if arch==4 else endian_str()+"Q"
    return struct.unpack( fmt, mem)[0]


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


@gef_obsolete_function
def read_memory_until_null(address, max_length=-1):
    """
    Slow method to read all the bytes in memory starting from
    `address` until we hit a null byte, or `max_length` is reached
    """
    i = 0

    if PYTHON_MAJOR == 2:
        buf = ''
        while True:
            try:
                c = read_memory(address + i, 1)[0]
                if c == '\x00':
                    break
                buf += c
                i += 1
                if max_length > 0 and i == max_length:
                    break
            except:
                break
        return buf

    else:
        buf = []
        while True:
            try:
                c = read_memory(address + i, 1)[0]
                if c == 0x00:
                    break
                buf.append( c )
                i += 1
                if max_length > 0 and i == max_length:
                    break
            except:
                break

        return bytes(buf)


def read_cstring_from_memory(address):
    char_ptr = gdb.lookup_type("char").pointer()
    res = gdb.Value(address).cast(char_ptr).string()
    for c in ("\n", "\t", "\d"):
        i = res.find(c)
        if i==-1: continue
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
    try:
        pid = get_frame().pid
        return pid > 0
    except gdb.error as e:
        return False

    return False


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
    if "gef-remote.pid" in __config__.keys():
        return __config__.get("gef-remote.pid")[0]
    return get_frame().pid


def get_filename():
    if "gef-remote.filename" in __config__.keys():
        return __config__.get("gef-remote.filename")[0]
    return gdb.current_progspace().filename

@memoize
def get_process_maps():
    sections = []

    try:
        pid = get_pid()
        proc = __config__.get("gef-remote.proc_directory")[0]
        f = open('%s/%d/maps' % (proc, pid))
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
            filename = get_filename()

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


# dirty hack, from https://github.com/longld/peda
def define_user_command(cmd, code):
    if PYTHON_MAJOR == 3:
        commands = bytes( "define {0}\n{1}\nend".format(cmd, code), "UTF-8" )
    else:
        commands = "define {0}\n{1}\nend".format(cmd, code)

    fd, fname = tempfile.mkstemp()
    os.write(fd, commands)
    os.close(fd)
    gdb.execute("source %s" % fname)
    os.unlink(fname)
    return


def get_terminal_size():
    """
    Portable function to retrieve the current terminal size.
    """
    cmd = [which("stty"), "size"]
    tty_rows, tty_columns = gef_execute_external(cmd).strip().split()
    return int(tty_rows), int(tty_columns)


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
        filename = get_filename()

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

    raise GefUnsupportedMode("GEF is running under an unsupported mode, functions will not work")

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
    return "gef-remote.target" in __config__.keys()


def generate_msf_pattern(length):
    """
    Create a Metasploit-like pattern whose length is specified by argument.
    """
    pattern = b""
    for mj in range(ord('A'), ord('Z')+1) :                         # from A to Z
        for mn in range(ord('a'), ord('z')+1) :                     # from a to z
            for dg in range(ord('0'), ord('9')+1) :                 # from 0 to 9
                for extra in "~!@#$%&*()-_+={}[]|;:<>?/":           # adding extra chars
                    for c in (chr(mj), chr(mn), chr(dg), extra):
                        if len(pattern) == length :
                            return pattern
                        else:
                            pattern += c.encode("utf-8")

        return b""


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

#
# Breakpoints
#
class FormatStringBreakpoint(gdb.Breakpoint):
    """Inspect stack for format string"""
    def __init__(self, spec, num_args):
        super(FormatStringBreakpoint, self).__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self):
        if is_arm():
            regs = ['$r0','$r1','$r2','$r3']
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        if is_aarch64():
            regs = ['$x0','$x1','$x2','$x3']
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_x86_64():
            regs = ['$rdi', '$rsi', '$rdx', '$rcx', '$r8', '$r9']
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_sparc():
            regs = ['$i0', '$i1', '$i2','$i3','$i4', '$i5' ]
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_mips():
            regs = ['$a0','$a1','$a2','$a3']
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_powerpc():
            regs = ['$r3', '$r4', '$r4','$r5', '$r6']
            ptr = regs[self.num_args]
            addr = lookup_address( get_register_ex( ptr ) )

        elif is_x86_32():
            sp = get_sp()
            m = get_memory_alignment(to_byte=True)
            val = sp + (self.num_args * m) + m
            ptr = read_int_from_memory( val )
            addr = lookup_address( ptr )

            # for pretty printing
            ptr = hex(ptr)

        else :
            raise NotImplementedError("Architecture '%s' not supported yet for FormatStringBreakpoint.")

        if addr is None:
            return False

        if addr.section.permission.value & Permission.WRITE:
            content = read_cstring_from_memory(addr.value)

            print((titlify("Format String Detection")))
            info("Possible insecure format string '%s' %s %#x: '%s'" % (ptr, right_arrow(), addr.value, content))
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
# Functions
#

# credits: http://tromey.com/blog/?p=515
class CallerIs (gdb.Function):
    """Return True if the calling function's name is equal to a string.
    This function takes one or two arguments."""

    def __init__ (self):
        super (CallerIs, self).__init__ ("caller_is")
        return

    def invoke (self, name, nframes = 1):
        frame = gdb.get_current_frame ()
        while nframes > 0:
            frame = frame.get_prev ()
            nframes = nframes - 1
        return frame.get_name () == name.string ()

CallerIs()



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
        super(GenericCommand, self).__init__(self._cmdline_, command_type, complete_type, True)
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


class ProcessIdCommand(GenericCommand):
    """ProcessIdCommand: print the process id of the process being debugged."""

    _cmdline_ = "pid"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            err("No process alive")
            return
        print("%d" % get_pid())
        return


class IdaInteractCommand(GenericCommand):
    """IDA Interact: set of commands to interact with IDA."""

    _cmdline_ = "ida-interact"
    _syntax_  = "%s METHOD [ARGS]" % _cmdline_

    def __init__(self):
        super(IdaInteractCommand, self).__init__()
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
            sock = None
        return sock

    def do_invoke(self, argv):
        return self.call(argv)

    def call(self, argv):
        sock = self.connect()
        if sock is None:
            return

        if len(argv)==0 or argv[0] in ("-h", "--help"):
            method_name = argv[1] if len(argv)>1 else None
            self.usage(sock, method_name)
            return

        try:
            method = getattr(sock, argv[0])
            if len(argv) > 1:
                args = argv[1:]
                res = method(*args)
            else:
                res = method()

            if res in (0, True):
                ok("Success")
            else:
                err("Error: retcode={}".format(res))
        except:
            del sock

        return

    def usage(self, sock=None, meth=None):
        super(IdaInteractCommand, self).usage()
        if sock is None:
            return

        if meth:
            meth = meth.replace("ida.", "")
            print(titlify(meth))
            print(sock.system.methodHelp(meth))
            return

        info("Listing methods: ")
        for m in sock.system.listMethods():
            if m.startswith("system."): continue
            print(titlify(m))
            print(sock.system.methodHelp(m))
        return


class SearchPatternCommand(GenericCommand):
    """SearchPatternCommand: search a pattern in memory."""

    _cmdline_ = "search-pattern"
    _syntax_  = "%s PATTERN" % _cmdline_
    _aliases_ = ["grep", ]

    def __init__(self):
        super(SearchPatternCommand, self).__init__()
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
                print("""{:#x}-{:#x} {:s}  "{:s}" """.format(loc[0], loc[1], right_arrow(), Color.pinkify(loc[2])))
        return

    def do_invoke(self, argv):
        if not is_alive():
            err("No process alive")
            return

        if len(argv)!=1:
            self.usage()
            return

        pattern = argv[0]
        info("Searching '{:s}' in memory".format(Color.yellowify(pattern)))
        self.search_pattern(pattern)
        return


class FlagsCommand(GenericCommand):
    """Edit flags in a human friendly wait"""

    _cmdline_ = "edit-flags"
    _syntax_  = "%s [+|-]FLAGNAME ([+|-]FLAGNAME)*" % _cmdline_
    _aliases_ = ["flags", ]

    def __init__(self):
        super(FlagsCommand, self).__init__()
        return

    def do_invoke(self, argv):
        for flag in argv:
            if len(flag)<2:
                continue

            action = flag[0]
            name = flag[1:].lower()

            if action not in ('+', '-'):
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
            else:
                new_flags = old_flag & ~(1<<off)

            gdb.execute("set (%s) = %#x" % (flag_register(), new_flags))

        print(flag_register_to_human())
        return


class ChangePermissionCommand(GenericCommand):
    """Change a page permission. By default, it will change it to RWX."""

    _cmdline_ = "set-permission"
    _syntax_  = "%s LOCATION [PERMISSION]" % _cmdline_
    _aliases_ = ["mprotect", ]

    def __init__(self):
        super(ChangePermissionCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def pre_load(self):
        try:
            import keystone
        except ImportError as ioe:
            msg = "Missing Python `keystone` package. "
            msg+= "Install with `pip{} install keystone`".format(PYTHON_MAJOR)
            raise GefMissingDependencyException( msg )
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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
        super(UnicornEmulateCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("verbose", False)
        self.add_setting("show_disassembly", False)
        return

    def help(self):
        h = "%s\n" % self._syntax_
        h+= "\t-f LOCATION specifies the start address of the emulated run (default $pc).\n"
        h+= "\t-t LOCATION specifies the end address of the emulated run.\n"
        h+= "\t-e generates a standalone Python script from the current runtime context.\n"
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

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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

            elif o == "-e":   to_script = a
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

        if to_script:
            content+= "#!/usr/bin/python"
            content+= """

import capstone, unicorn


def disassemble(code, addr):
    cs = capstone.Cs(%s, %s)
    for i in cs.disasm(str(code),addr):
        return i

def hook_code(emu, address, size, user_data):
    print(">> Executing instruction at 0x{:x}".format(address))\n
    code = emu.mem_read(address, size)
    insn = disassemble(code, address)
    print(">>> 0x{:x}: {:s} {:s}".format(insn.address, insn.mnemonic, insn.op_str))\n
    return


""" % get_capstone_arch()

        unicorn = sys.modules['unicorn']
        if verbose:
            info("Initializing Unicorn engine")

        if to_script:
            content += "emu = unicorn.Uc(%s, %s)\n" % (arch, mode)
        else:
            emu = unicorn.Uc(arch, mode)

        if verbose:
            info("Populating registers")

        for r in all_registers():
            gregval = get_register_ex(r)
            if to_script:
                content += "emu.reg_write(%s, %#x)\n" % (unicorn_registers[r], gregval)
            else:
                emu.reg_write(unicorn_registers[r], gregval)
                start_regs[r] = gregval

        if to_script:
            for r in all_registers():
                content += """print(">> %s = 0x{:x}".format(emu.reg_read(%s)))\n""" % (r, unicorn_registers[r])

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
                content += "emu.mem_map(%#x, %d, %d)\n" % (FS, page_sz, 3)
                content += "emu.mem_map(%#x, %d, %d)\n" % (GS, page_sz, 3)
                content += "emu.reg_write(%s, %#x)\n" % (unicorn_registers['$fs    '], FS)
                content += "emu.reg_write(%s, %#x)\n" % (unicorn_registers['$gs    '], GS)
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
                    content += "emu.mem_map(%#x, %d, %d)\n" % (page_start, size, perm.value)
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
                        with open("/tmp/gef-%#x.raw"%page_start, "wb") as f:
                            f.write(bytes(code))

                        content += "# Importing %s: %#x-%#x\n"%(sect.path, page_start, page_end)
                        content += "data=open('/tmp/gef-%#x.raw', 'r').read()\n" % page_start
                        content += "emu.mem_write(%#x, data)\n" % (page_start, )
                        content += "\n"

                    else:
                        emu.mem_write(page_start, bytes(code))
            except Exception as e:
                warn("Cannot copy page=%#x-%#x : %s" % (page_start, page_end, e))
                continue


        if to_script:
            content += "emu.hook_add(unicorn.UC_HOOK_CODE, hook_code)\n"
        else:
            emu.hook_add(unicorn.UC_HOOK_BLOCK, self.hook_block)
            emu.hook_add(unicorn.UC_HOOK_CODE, self.hook_code)

        if to_script:
            content += "\n"*2
            content += "try:\n    emu.emu_start(%#x, %#x)\n" % (start_insn_addr, end_insn_addr)
            content += "except Exception as e:\n    emu.emu_stop()\n    print('Error: {}'.format(e))"
            content += "\n"*2

            for r in all_registers():
                content += """print(">> %s = 0x{:x}".format(emu.reg_read(%s)))\n""" % (r, unicorn_registers[r])

            content += "\n\n# Unicorn script generated by gef\n"

            with open(to_script, 'w') as f:
                f.write(content)

            info("Unicorn script generated as '%s'" % to_script)
            return

        ok("Starting emulation: %#x %s %#x" % (start_insn_addr,
                                               right_arrow(),
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
    _syntax_  = "%s -t TARGET -p PID [OPTIONS]" % _cmdline_

    def __init__(self):
        super(RemoteCommand, self).__init__()
        self.add_setting("proc_directory", "/proc")
        return

    def do_invoke(self, argv):
        target = None
        rpid = -1
        update_solib = False
        fetch_all_libs = False
        download_lib = None
        opts, args = getopt.getopt(argv, "t:p:hUD:")
        for o,a in opts:
            if   o == "-t":   target = a
            elif o == "-p":   rpid = int(a)
            elif o == "-U":   update_solib = True
            elif o == "-D":   download_lib = a
            elif o == "-U":   fetch_all_libs = True
            elif o == "-h":
                self.help()
                return

        if target is not None:
            if rpid not in range(1, 65536):
                err("Invalid syntax, see -h for help.")
                return

            self.setup_remote_environment(target, rpid, update_solib)
            return

        if download_lib is not None:
            if not is_remote_debug():
                warn("No remote session active.")
                return

            pid = self.get_setting("pid")
            fil = self.download_file(pid, download_lib)
            if fil is None:
                err("Failed to download remote file")
                return
            ok("Download success: %s %s %s" % (download_lib, right_arrow(), fil))
            if update_solib:
                self.refresh_shared_library_path()
            return

        err("No action defined")
        return


    def setup_remote_environment(self, target, pid, update_solib=False):
        # cleaning memoized cache
        gdb.execute("reset-cache")

        if not self.connect_target(target):
            err("Failed to connect to %s" % target)
            return

        ok("Connected to '%s'" % target)

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

        directory  = '%s/%d' % (tempfile.gettempdir(), pid)
        gdb.execute("file %s" % infos["exe"])

        self.add_setting("root", directory)
        self.add_setting("proc_directory", directory + '/proc')
        self.add_setting("pid", pid)
        self.add_setting("filename", infos["exe"])
        self.add_setting("target", target)

        ok("Remote information loaded, remember to clean '%s' when your session is over" % directory)
        if update_solib:
            self.refresh_shared_library_path()
        return


    def connect_target(self, target):
        """Connect to remote target and get symbols. To prevent `gef` from requesting information
        not fetched just yet, we disable the context disable when connection was successful."""
        disable_context()
        try:
            gdb.execute("target remote {0}".format(target))
            ret = True
        except Exception as e:
            err(str(e))
            ret = False
        enable_context()
        return ret


    def download_file(self, pid, target):
        """Download filename `target` inside the mirror tree in /tmp"""
        try:
            local_root = '{0:s}/{1:d}'.format(tempfile.gettempdir(), pid)
            local_path = local_root + '/' + os.path.dirname( target.replace("target:", "") )
            local_name = local_path + '/' + os.path.basename( target )
            gef_makedirs(local_path)
            gdb.execute("remote get {0:s} {1:s}".format(target, local_name))
        except Exception as e:
            err(str(e))
            local_name = None
        return local_name


    def load_target_proc(self, pid, info):
        """Download one item from /proc/pid"""
        remote_name = "/proc/{:d}/{:s}".format(pid, info)
        return self.download_file(pid, remote_name)


    def refresh_shared_library_path(self):
        dirs = [r for r, d, f in os.walk( self.get_setting("root") )]
        path = ":".join(dirs)
        gdb.execute("set solib-search-path %s" % (path,))
        return


    def help(self):
        h = "%s\n" % self._syntax_
        h+= "\t-t TARGET (mandatory) specifies the host:port, serial port or tty to connect to.\n"
        h+= "\t-p PID (mandatory) specifies PID of the debugged process on gdbserver's end.\n"
        h+= "\t-U will update gdb `solib-search-path` attribute to include the files downloaded from server (default: False).\n"
        h+= "\t-A will download *ALL* the remote shared libraries and store them in the new environment. This command can take a few minutes to complete (default: False).\n"
        h+= "\t-D LIB will download the remote library called LIB.\n"
        info(h)
        return


class PatchCommand(GenericCommand):
    """Patch the instruction pointed by parameters with NOP. If the return option is
    specified, it will set the return register to the specific value."""

    _cmdline_ = "patch"
    _syntax_  = "%s [-r VALUE] [-p] [-h] [LOCATION]" % _cmdline_


    def __init__(self):
        super(PatchCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
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


    def onetime_patch(self, loc, retval):
        if not is_alive():
            warn("No debugging session active")
            return

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
            msg+= "Install with `pip{} install capstone`".format(PYTHON_MAJOR)
            raise GefMissingDependencyException( msg )
        return


    def __init__(self):
        super(CapstoneDisassembleCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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
            m = Color.boldify(Color.blueify(format_address(insn.address))) + "\t"

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
            m+= Color.redify("\t"+left_arrow()+" $pc ")

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

    def __init__(self):
        super(GlibcHeapCommand, self).__init__()
        return

    def do_invoke(self, argv):
        self.usage()
        return


class GlibcHeapArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap arenas"
    _syntax_  = "%s" % _cmdline_

    def __init__(self):
        super(GlibcHeapArenaCommand, self).__init__()
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("Process not alive")
            return

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
        super(GlibcHeapChunkCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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

    def __init__(self):
        super(GlibcHeapBinsCommand, self).__init__()
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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
        bin_fw, bin_bk = arena.bins[bin_idx+2], arena.bins[bin_idx*2+1]
        fw, bk = arena.bin(bin_idx)

        ok("Found base for bin({:d}): fw={:#x}, bk={:#x}".format(bin_idx, fw, bk))
        if bk == fw:
            ok("Empty")
            return

        m = ""
        while fw != bin1_fd:
            chunk = GlibcChunk(fw)
            m+= "{:s}  {:s}  ".format(right_arrow(), str(chunk))
            fw = chunk.get_fwd_ptr()

        print(m)
        return

class GlibcHeapFastbinsYCommand(GenericCommand):
    """Display information on the fastbinsY on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123"""

    _cmdline_ = "heap bins fast"
    _syntax_  = "%s [ARENA_LOCATION]" % _cmdline_

    def __init__(self):
        super(GlibcHeapFastbinsYCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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
                    m+= "{:s}  {:s}  ".format(right_arrow(), str(chunk))
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
        super(GlibcHeapUnsortedBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        arena_addr =  "*%#x"%int(argv[0],16) if len(argv)==1 else "main_arena"
        print(titlify("Information on Unsorted Bin of arena '{:s}'".format(arena_addr)))
        GlibcHeapBinsCommand.pprint_bin(arena_addr, 0)
        return

class GlibcHeapSmallBinsCommand(GenericCommand):
    """Convience command for viewing small bins"""

    _cmdline_ = "heap bins small"
    _syntax_  = "%s [ARENA_LOCATION]" % _cmdline_

    def __init__(self):
        super(GlibcHeapSmallBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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
        super(GlibcHeapLargeBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        arena_addr = "*%#x"%int(argv[0],16) if len(argv)==1 else "main_arena"
        print(titlify("Information on Large Bins of arena '{:s}'".format(arena_addr)))
        for i in range(64, 127):
            GlibcHeapBinsCommand.pprint_bin(arena_addr, i)
        return


class DumpMemoryCommand(GenericCommand):
    """Dump chunks of memory into raw file on the filesystem. Dump file
    name template can be defined in GEF runtime config"""

    _cmdline_ = "dump-memory"
    _syntax_  = "%s LOCATION [SIZE]" % _cmdline_


    def __init__(self):
        super(DumpMemoryCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("dumpfile_prefix", "./dumpmem-")
        self.add_setting("dumpfile_suffix", "raw")
        return

    def do_invoke(self, argv):
        argc = len(argv)

        if argc not in (1, 2):
            err("Invalid arguments number")
            self.usage()
            return

        prefix = self.get_setting("dumpfile_prefix")
        suffix = self.get_setting("dumpfile_suffix")

        start_addr = align_address( long(gdb.parse_and_eval( argv[0] )) )
        filename = "%s%#x.%s" % (prefix, start_addr, suffix)
        size = long(argv[1]) if argc==2 and argv[1].isdigit() else 0x100

        with open(filename, "wb") as f:
            mem = read_memory( start_addr, size )
            f.write( mem )

        info("Dumped %d bytes from %#x in '%s'" % (size, start_addr, filename))
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
            print(("'%s'\t'%s'" % (alias_name, ";".join(__aliases__[alias_name]))))
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

    def do_invoke(self, argv):
        regs = []

        if not is_alive():
            warn("No debugging session active")
            return

        if len(argv) > 0:
            regs = [ reg for reg in all_registers() if reg.strip() in argv ]
        else:
            regs = all_registers()

        for regname in regs:
            reg = gdb.parse_and_eval(regname)
            line = Color.boldify(Color.redify(regname)) + ": "

            if str(reg.type) == 'builtin_type_sparc_psr':  # ugly but more explicit
                line+= "%s" % reg

            elif reg.type.code == gdb.TYPE_CODE_FLAGS:
                desc_flag = flag_register()
                line+= "%s" % (Color.boldify(str(reg))) if desc_flag == "" else desc_flag

            else:
                addr = align_address( long(reg) )
                line+= Color.boldify(Color.blueify(format_address(addr)))
                addrs = DereferenceCommand.dereference_from(addr)

                if len(addrs) > 1:
                    sep = " %s " % right_arrow()
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
                    print(("\t".join([sid, arch, cmd])))
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


class CtfExploitTemplaterCommand(GenericCommand):
    """Generates a ready-to-use exploit template for CTF."""

    _cmdline_ = "ctf-exploit-templater"
    _syntax_  = "%s HOST PORT [/path/exploit.py]" % _cmdline_

    def __init__(self):
        super(CtfExploitTemplaterCommand, self).__init__()
        self.add_setting("exploit_path", "./gef-exploit.py")
        return

    def do_invoke(self, argv):
        argc = len(argv)

        if argc not in (2, 3):
            err("%s" % self._syntax_)
            return

        host, port = argv[0], argv[1]
        path = argv[2] if argc==3 else self.get_setting("exploit_path")

        asm_def = ""
        a, m = get_keystone_arch(to_string=True)
        asm_def = """
def asm(code, arch="%s", mode=%s):
    import keystone
    ks = keystone.Ks(arch, mode)
    try: enc, cnt = ks.asm(code)
    except: enc = []
    return bytearray(enc)
"""%(a, m,)

        with open(path, "w") as f:
            f.write( CTF_EXPLOIT_TEMPLATE.format(host=host, port=port, asm=asm_def) )

        info("Exploit script written as '%s'" % path)
        return


class ROPgadgetCommand(GenericCommand):
    """ROPGadget (http://shell-storm.org/project/ROPgadget) plugin"""

    _cmdline_ = "ropgadget"
    _syntax_  = "%s  [OPTIONS]" % _cmdline_


    def __init__(self):
        super(ROPgadgetCommand, self).__init__()
        return

    def pre_load(self):
        try:
            import ropgadget

        except ImportError as ie:
            msg = "Missing Python `ropgadget` package. "
            msg+= "Install with `pip{} install ropgadget`".format(PYTHON_MAJOR)
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
            setattr(args, "binary", get_filename())

        info("Using binary: %s" % args.binary)
        return True


class FileDescriptorCommand(GenericCommand):
    """Enumerate file descriptors opened by process."""

    _cmdline_ = "fd"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        if is_remote_debug():
            warn("'%s' cannot be used on remote debugging" % self._cmdline_)
            return

        pid = get_pid()
        proc = __config__.get("gef-remote.proc_directory")[0]
        path = "%s/%d/fd" % (proc, pid)

        for fname in os.listdir(path):
            fullpath = path+"/"+fname
            if os.path.islink(fullpath):
                info("- %s %s %s" % (fullpath, right_arrow(), os.readlink(fullpath)))

        return


class AssembleCommand(GenericCommand):
    """Inline code assemble. Architecture can be set in GEF runtime config (default is
    x86). """

    _cmdline_ = "assemble"
    _syntax_  = "%s [-a ARCH] [-m MODE] [-e] [-s] instruction;[instruction;...instruction;])" % _cmdline_
    _aliases_ = ["asm", ]

    def __init__(self, *args, **kwargs):
        super(AssembleCommand, self).__init__()
        return

    def pre_load(self):
        try:
            import keystone
        except ImportError as ioe:
            msg = "Missing Python `keystone` package. "
            msg+= "Install with `pip{} install keystone`".format(PYTHON_MAJOR)
            raise GefMissingDependencyException( msg )
        return

    def do_invoke(self, argv):
        keystone = sys.modules["keystone"]
        arch_s, mode_s, big_endian, as_shellcode = None, None, False, False
        opts, args = getopt.getopt(argv, "a:m:esh")
        for o,a in opts:
            if o=="-a": arch_s = a.upper()
            if o=="-m": mode_s = a.upper()
            if o=="-e": big_endian = True
            if o=="-s": as_shellcode = True
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

        for insn in insns:
            res = keystone_assemble(insn, arch, mode, raw=False)
            if res is None:
                print("(Invalid)")
                continue

            if as_shellcode:
                res = """sc+="{0:s}" """.format(res)

            print("{0:60s} # {1}".format(res, insn))

        return


class InvokeCommand(GenericCommand):
    """Invoke an external command and display result."""

    _cmdline_ = "system"
    _syntax_  = "%s [COMMAND]" % _cmdline_

    @gef_obsolete_function
    def do_invoke(self, argv):
        ret = gef_execute_external( argv )
        print(( "%s" % ret ))
        return


class ProcessListingCommand(GenericCommand):
    """List and filter process."""

    _cmdline_ = "process-search"
    _syntax_  = "%s [PATTERN]" % _cmdline_
    _aliases_ = ["ps", ]

    def __init__(self):
        super(ProcessListingCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
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

        filename = argv[0] if len(argv) > 0 else get_filename()
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

                # todo finish
              ]

        for title, content in data:
            print(("{:<30}: {}".format(Color.boldify(title), content)))

        # todo finish
        return


class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it."""

    _cmdline_ = "entry-break"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if get_filename() is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        syms = ["main", "__libc_start_main", "__uClibc_main"]
        for sym in syms:
            try:
                value = gdb.parse_and_eval(sym)
                info("Breaking at '%s'" % value)
                gdb.execute("tbreak %s" % sym)
                info("Starting execution")
                gdb.execute("run")
                return

            except gdb.error as gdb_error:
                if 'The "remote" target does not support "run".' in str(gdb_error):
                    # this case can happen when doing remote debugging
                    gdb.execute("continue")
                    return
                # otherwise, simply continue with next symbol
                info("Could not solve `%s` symbol" % sym)
                continue

        # break at entry point - should never fail
        elf = get_elf_headers()
        if elf is None:
            return
        value = elf.e_entry
        if value:
            info("Breaking at entry-point: %#x" % value)
            gdb.execute("tbreak *%#x" % value)
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
        super(ContextCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("enable", True)
        self.add_setting("show_stack_raw", False)
        self.add_setting("nb_registers_per_line", int(get_terminal_size()[1]/30))
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


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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
        self.update_registers()

        self.context_title('')
        return

    def context_title(self, m):
        trail = horizontal_line()*2
        title = "[{}]{}".format(m,trail) if len(m) else "{}".format(trail)
        title = horizontal_line()*(self.tty_columns-len(title)) + title
        print(( Color.boldify( Color.blueify(title)) ))
        return

    def context_regs(self):
        if self.get_setting("show_registers")==False: return

        self.context_title("registers")

        i = 1
        line = ""

        for reg in all_registers():
            line += "%s  " % (Color.greenify(reg))

            try:
                r = gdb.parse_and_eval(reg)
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

            if new_value_type_flag:
                line += "%s " % (new_value)
            else:
                new_value = align_address( long(new_value) )
                old_value = align_address( long(old_value) )

                if new_value == old_value:
                    line += "%s " % (format_address(new_value))
                else:
                    line += "%s " % Color.boldify(Color.redify(format_address(new_value)))

            if (i % self.get_setting("nb_registers_per_line")==0) :
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
                InspectStackCommand.inspect_stack(sp, nb_lines)

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
                line = u""
                if addr < pc:
                    line+= Color.grayify("%#x\t %s" % (addr, content,) )
                elif addr == pc:
                    line+= Color.boldify(Color.redify("%#x\t %s \t\t %s $pc" % (addr, content, left_arrow())))
                else:
                    line+= "%#x\t %s" % (addr, content)

                print(line)

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
                print(Color.boldify(Color.redify("%4d\t %s \t\t %s $pc\t" % (i+1, lines[i], left_arrow(),))) + extra_info)

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

                        f = " " + right_arrow() + " "
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
            self.old_registers[reg] = get_register_ex(reg)
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
    _syntax_  = "%s (q|d|w|b) LOCATION L[SIZE] [UP|DOWN]" % _cmdline_
    _aliases_ = ["xd",]

    def do_invoke(self, argv):
        argc = len(argv)
        if not is_alive():
            warn("No debugging session active")
            return

        if argc < 2:
            self.usage()
            return

        if argv[0] not in ("q", "d", "w", "b"):
            self.usage()
            return

        fmt = argv[0]
        read_from = align_address( long(gdb.parse_and_eval(argv[1])) )
        read_len = 10
        up_to_down = True

        if argc >= 3:
            for arg in argv[2:]:
                if arg.startswith("L"):
                    if arg[1:].isdigit():
                        read_len = long(arg[1:])
                        continue

                if arg in ("UP", "Up", "up"):
                    up_to_down = True
                    continue

                if arg in ("DOWN", "Down", "down"):
                    up_to_down = False
                    continue

        self._hexdump(read_from, read_len, fmt, up_to_down)
        return


    def _hexdump(self, start_addr, length, arrange_as, from_up_to_down=True):
        elf = get_elf_headers()
        if elf is None:
            return
        endianness = "<" if elf.e_endianness == 0x01 else ">"
        i = 0

        formats = { 'q': ('Q', 8),
                    'd': ('I', 4),
                    'w': ('H', 2),
                    'b': ('B', 1),
        }
        r, l = formats[arrange_as]
        fmt_str = "<%#x+%.4x> %#."+str(l*2)+"x"
        fmt_pack = endianness + r
        lines = []

        while i < length:
            cur_addr = start_addr + i*l
            mem = read_memory(cur_addr, l)
            val = struct.unpack(fmt_pack, mem)[0]
            lines.append(fmt_str % (start_addr, i*l, val))
            i += 1

        if not from_up_to_down:
            lines.reverse()

        print("\n".join(lines))
        return


class DereferenceCommand(GenericCommand):
    """Dereference recursively an address and display information"""

    _cmdline_ = "dereference"
    _syntax_  = "%s [LOCATION] [NB]" % _cmdline_

    def __init__(self):
        super(DereferenceCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_recursion", 10)
        return

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        if len(argv) < 1:
            err("Missing argument (register/address)")
            return

        nb = int(argv[1]) if len(argv)==2 and argv[1].isdigit() else 1
        init_addr = align_address( long(gdb.parse_and_eval(argv[0])) )
        print("Dereferencing %d entr%s from %s " % (nb,
                                                    "ies" if nb>1 else "y",
                                                    Color.yellowify(format_address(init_addr))))

        for i in range(0, nb):
            addr = init_addr + (get_memory_alignment(to_byte=True) * i)
            addrs = DereferenceCommand.dereference_from(addr)
            print(("%s" % (Color.boldify("   %s   " % right_arrow()).join(addrs), )))

        return


    @staticmethod
    def dereference_from(addr):
        prev_addr_value = None
        deref = addr
        msg = []
        max_recursion = max(int(__config__["dereference.max_recursion"][0]), 1)

        while max_recursion:
            value = align_address( long(deref) )
            addr  = lookup_address( value )

            if addr is None:
                msg.append( "%#x" % ( long(deref) & 0xffffffffffffffff ))
                break

            if addr.value == prev_addr_value:
                msg.append( "[loop detected]")
                break

            msg.append( "%s" % format_address( long(deref) ))

            if addr.section:
                is_in_text_segment = hasattr(addr.info, "name") and ".text" in addr.info.name
                if addr.section.is_executable() and is_in_text_segment:
                    cmd = gdb.execute("x/i %#x" % value, to_string=True).replace("=>", '')
                    cmd = re.sub('\s+',' ', cmd.strip()).split(" ", 1)[1]
                    msg.append( "%s" % Color.redify(cmd) )
                    break

                elif addr.section.permission.value & Permission.READ:
                    if is_readable_string(value):
                        s = read_cstring_from_memory(value)
                        if len(s) >= 50:
                            s = s[:50] + "[...]"

                        msg.append( '"%s"' % Color.greenify(s))
                        break

            prev_addr_value = addr.value
            deref = dereference(value)
            max_recursion -= 1

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

            print(("%s" % msg))

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

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        vmmap = get_process_maps()
        if vmmap is None or len(vmmap)==0:
            err("No address mapping information found")
            return

        if is_elf64():
            print(("%18s %18s %18s %4s %s" % ("Start", "End", "Offset", "Perm", "Path")))
        else:
            print(("%10s %10s %10s %4s %s" % ("Start", "End", "Offset", "Perm", "Path")))
        for entry in vmmap:
            l = []
            l.append( format_address( entry.page_start ))
            l.append( format_address( entry.page_end ))
            l.append( format_address( entry.offset ))

            if entry.permission.value == (Permission.READ|Permission.WRITE|Permission.EXECUTE) :
                l.append( Color.boldify(Color.redify(str(entry.permission))) )
            else:
                l.append( str(entry.permission) )

            l.append( entry.path )

            print(" ".join(l))
        return


class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary (Truth is out there)."""

    _cmdline_ = "xfiles"
    _syntax_  = "%s [name]" % _cmdline_

    def do_invoke(self, args):
        if not is_alive():
            warn("Debugging session is not active")
            warn("Result may be incomplete (shared libs, etc.)")
            return

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


    def do_invoke (self, argv):
        if not is_alive():
            warn("Debugging session is not active")
            return

        if len(argv) < 1:
            err ("At least one valid address must be specified")
            return

        for sym in argv:
            try:
                addr = align_address( parse_address(sym) )
                print(( titlify("xinfo: %#x" % addr )))
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
            print(("Found %s" % format_address(addr.value)))
            print(("Page: %s %s %s (size=%#x)" % (format_address(sect.page_start),
                                                  right_arrow(),
                                                  format_address(sect.page_end),
                                                  sect.page_end-sect.page_start)))
            print(("Permissions: %s" % sect.permission))
            print(("Pathname: %s" % sect.path))
            print(("Offset (from page): +%#x" % (addr.value-sect.page_start)))
            print(("Inode: %s" % sect.inode))

        if info:
            print(("Segment: %s (%s-%s)" % (info.name,
                                            format_address(info.zone_start),
                                            format_address(info.zone_end))))

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


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

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


    def do_invoke(self, argv):
        if len(argv) not in (1, 2):
            self.usage()
            return

        if not is_alive():
            warn("Debugging session is not active")
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

        gdb.execute( "set logging overwrite" )
        gdb.execute( "set logging file %s" % logfile)
        gdb.execute( "set logging redirect on" )
        gdb.execute( "set logging on" )

        disable_context()

        self._do_trace(loc_start, loc_end, depth)

        enable_context()

        gdb.execute( "set logging redirect off" )
        gdb.execute( "set logging off" )

        ok("Done, logfile stored as '%s'" % logfile)
        info("Hint: import logfile with `ida_color_gdb_trace.py` script in IDA to visualize path")
        return


    def _do_trace(self, loc_start, loc_end, depth):
        loc_old = 0
        loc_cur = loc_start
        frame_count_init = self.get_frames_size()

        print("#")
        print("# Execution tracing of %s" % get_filename())
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
    """Metasploit-like pattern generation/search"""

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
    """Metasploit-like pattern generation"""

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
        patt = generate_msf_pattern(size)
        print(patt.decode("utf-8"))
        return


class PatternSearchCommand(GenericCommand):
    """Metasploit-like pattern search"""

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

        buf = generate_msf_pattern(size)
        found = False

        off = buf.find(pattern_le)
        if off >= 0:
            ok("Found at offset %d (little-endian search)" % off)
            found = True

        off = buf.find(pattern_be)
        if off >= 0:
            ok("Found at offset %d (big-endian search)" % off)
            found = True

        if not found:
            err("Pattern not found")

        return


class InspectStackCommand(GenericCommand):
    """Exploiter-friendly top-down stack inspection command (peda-like)"""

    _cmdline_ = "inspect-stack"
    _syntax_  = "%s  [NbStackEntry]" % _cmdline_


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        nb_stack_block = 10
        argc = len(argv)
        if argc >= 1:
            try:
                nb_stack_block = long(argv[0])
            except ValueError:
                pass

        top_stack = get_register("$sp")
        self.inspect_stack(top_stack, nb_stack_block)
        return


    @staticmethod
    def inspect_stack(sp, nb_stack_block):
        sp = align_address( long(sp) )
        memalign = get_memory_alignment() >> 3

        def _do_inspect_stack(i):
            offset = i*memalign
            cur_addr = align_address( sp + offset )
            addrs = DereferenceCommand.dereference_from(cur_addr)
            sep = " %s " % right_arrow()
            l  = Color.boldify(Color.blueify( format_address(long(addrs[0], 16) )))
            l += vertical_line() + "+%#.2x: " % offset
            l += sep.join(addrs[1:])
            if cur_addr == sp:
                l += Color.boldify(Color.greenify( "\t\t"+ left_arrow() + " $sp" ))
            offset += memalign
            return l

        for i in range(nb_stack_block):
            value = _do_inspect_stack(i)
            print(value)

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

            filename = get_filename()

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

        print(("%s" % buf))
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

        for func_name, num_arg in dangerous_functions.items():
            FormatStringBreakpoint(func_name, num_arg)

        return


class GEFCommand(gdb.Command):
    """GEF main command: start with `gef help` """

    _cmdline_ = "gef"
    _syntax_  = "%s (config|help|save|restore)" % _cmdline_

    def __init__(self):
        super(GEFCommand, self).__init__(GEFCommand._cmdline_,
                                         gdb.COMMAND_SUPPORT)

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
                        HexdumpCommand,
                        CapstoneDisassembleCommand,
                        ContextCommand,
                        EntryPointBreakCommand,
                        ElfInfoCommand,
                        ProcessListingCommand,
                        InvokeCommand,
                        AssembleCommand,
                        FileDescriptorCommand,
                        ROPgadgetCommand,
                        InspectStackCommand,
                        CtfExploitTemplaterCommand,
                        ShellcodeCommand, ShellcodeSearchCommand, ShellcodeGetCommand,
                        DetailRegistersCommand,
                        SolveKernelSymbolCommand,
                        AliasCommand, AliasShowCommand, AliasSetCommand, AliasUnsetCommand, AliasDoCommand,
                        DumpMemoryCommand,
                        GlibcHeapCommand, GlibcHeapArenaCommand, GlibcHeapChunkCommand, GlibcHeapBinsCommand, GlibcHeapFastbinsYCommand, GlibcHeapUnsortedBinsCommand, GlibcHeapSmallBinsCommand, GlibcHeapLargeBinsCommand,
                        PatchCommand,
                        RemoteCommand,
                        UnicornEmulateCommand,
                        ChangePermissionCommand,
                        FlagsCommand,
                        SearchPatternCommand,
                        IdaInteractCommand,
                        ProcessIdCommand,

                        # add new commands here
                        # when subcommand, main command must be placed first
                        ]

        self.__cmds = [ (x._cmdline_, x) for x in self.classes ]
        self.__loaded_cmds = []

        self.load()
        self.__doc__ = self.generate_help()
        return


    @property
    def loaded_command_names(self):
        return [ x[0] for x in self.__loaded_cmds ]


    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) < 1 :
            err("Missing command for gef -- `gef help` for help -- `gef config` for configuring")
            return

        cmd = argv[0]
        if cmd == "help":
            self.help()
        elif cmd == "config":
            self.config(*argv[1:])
        elif cmd == "save":
            self.save()
        elif cmd == "restore":
            self.restore()
        else:
            err("Invalid command '%s' for gef -- type `gef help' for help" % ' '.join(argv))

        return


    def load(self, mod=None):
        """
        Load all the commands defined by GEF into GBD.
        If a configuration file is found, the settings are restored.
        """
        global __loaded__

        __loaded__ = []

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

            except Exception as e:
                warn("Failed to load `%s`: %s" % (cmd, e))

        self.__loaded_cmds = sorted(__loaded__, key=lambda x: x[1]._cmdline_)

        print(("%s, `%s' to start, `%s' to configure" % (Color.greenify("gef loaded"),
                                                         Color.redify("gef help"),
                                                         Color.redify("gef config"))))

        ver = "%d.%d" % (sys.version_info.major, sys.version_info.minor)
        nb_cmds = sum([1 for x in self.loaded_command_names if " " not in x])
        nb_sub_cmds = sum([1 for x in self.loaded_command_names if " " in x])
        print(("%s commands loaded (%s sub-commands), using Python engine %s" % (Color.greenify(str(nb_cmds)),
                                                                                 Color.greenify(str(nb_sub_cmds)),
                                                                                 Color.redify(ver))))

        if os.access(GEF_RC, os.R_OK):
            self.restore()
        return


    def generate_help(self):
        d = []
        d.append( titlify("GEF - GDB Enhanced Features") )

        for (cmd, class_name, obj) in self.__loaded_cmds:
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


    def help(self):
        print("Syntax: %s\n" % self._syntax_)
        print(self.__doc__)
        return


    def config(self, *args):
        argc = len(args)

        if not (0 <= argc <= 2):
            err("Invalid number of arguments")
            return

        if argc==1 and args[0] in ("debug_on", "debug_off"):
            if args[0] == "debug_on":
                enable_debug()
                info("Enabled debug mode")
            else:
                disable_debug()
                info("Disabled debug mode")
            return

        if argc==0 or argc==1:
            config_items = sorted( __config__ )
            plugin_name = args[0] if argc==1 and args[0] in self.loaded_command_names else ""
            print(( titlify("GEF configuration settings %s" % plugin_name) ))
            for key in config_items:
                if plugin_name not in key:
                    continue
                value, type = __config__.get(key, None)
                print( ("%-40s  (%s) = %s" % (key, type.__name__, value)) )
            return

        if "." not in args[0]:
            err("Invalid command format")
            return

        plugin_name, setting_name = args[0].split(".", 1)

        if plugin_name not in self.loaded_command_names:
            err("Unknown plugin '%s'" % plugin_name)
            return

        _curval, _type = __config__.get( args[0], (None, None) )
        if _type == None:
            err("Failed to get '%s' config setting" % (args[0], ))
            return

        try:
            if _type == bool:
                _newval = True if args[1]=="True" else False
            else:
                _newval = args[1]
                _type( _newval )

        except:
            err("%s expects type '%s'" % (args[0], _type.__name__))
            return

        __config__[ args[0] ] = (_newval, _type)
        return


    def save(self):
        """
        Saves the current configuration of GEF to disk
        """
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


    def restore(self):
        """
        Loads ~/.gef.rc and restore a former configuration of GEF
        """

        cfg = configparser.ConfigParser()
        cfg.read(GEF_RC)

        for section in cfg.sections():
            for optname in cfg.options(section):
                key = "%s.%s" % (section, optname)
                old_value, _type = __config__.get(key)
                try:
                    new_value = cfg.get(section, optname)
                    if _type == bool:
                        new_value = True if new_value=='True' else False
                    else:
                        new_value = _type(new_value)
                    __config__[key] = (new_value, _type)
                except:
                    warn("Could not restore '%s'" % optname)

        ok("Configuration from '%s' restored" % GEF_RC)
        return


def __gef_prompt__(current_prompt):
    prompt = "gef> " if PYTHON_MAJOR == 2 else "gef\u27a4  "
    return Color.CLEAR_LINE + Color.boldify(Color.redify(prompt))



if __name__  == "__main__":
    if ALLOW_UPDATE_ONLY:
        sys.exit(0)

    # setup prompt
    gdb.prompt_hook = __gef_prompt__

    # setup config
    gdb.execute("set confirm off")
    gdb.execute("set verbose off")
    gdb.execute("set height 0"),
    gdb.execute("set width 0")
    gdb.execute("set follow-fork-mode child")

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
    gdb.execute("alias -a g = run")

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
    GEFCommand()

    # post-loading stuff
    define_user_command("hook-stop", "context")


################################################################################
##
##  CTF exploit templates
##
CTF_EXPLOIT_TEMPLATE = """#!/usr/bin/env python
import socket, struct, sys, telnetlib, binascii

HOST = "{host:s}"
PORT = {port:s}

def hexdump(src, length=0x10):
    f=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)]) ; n=0 ; result=''
    while src:
       s,src = src[:length],src[length:]; hexa = ' '.join(["%02X"%ord(x) for x in s])
       s = s.translate(f) ; result += "%04X   %-*s   %s\\n" % (n, length*3, hexa, s); n+=length
    return result

def xor(data, key):  return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, itertools.cycle(key)))
def p16(i,signed=False): return struct.pack("<H", i) if not signed else struct.pack("<h", i)
def u16(i,signed=False): return struct.unpack("<H", i)[0] if not signed else struct.unpack("<h", i)[0]
def p32(i,signed=False): return struct.pack("<I", i) if not signed else struct.pack("<i", i)
def u32(i,signed=False): return struct.unpack("<I", i)[0] if not signed else struct.unpack("<i", i)[0]
def p64(i,signed=False): return struct.pack("<Q", i) if not signed else struct.pack("<q", i)
def u64(i,signed=False): return struct.unpack("<Q", i)[0] if not signed else struct.unpack("<q", i)[0]

def _xlog(x): sys.stderr.write(x + "\\n") ; sys.stderr.flush() ; return
def err(msg):  _xlog("[!] %s" % msg)
def ok(msg):   _xlog("[+] %s" % msg)
def dbg(msg):  _xlog("[*] %s" % msg)
def xd(msg):   _xlog("[*] Hexdump:\\n%s" % hexdump(msg))
{asm:s}

def build_socket(host, port):
    s = telnetlib.Telnet(HOST, PORT)
    ok("Connected to %s:%d" % (host, port))
    return s

def interact(s, live_tty=False):
    pty = \"\"\"python -c "import pty;pty.spawn('/bin/bash')" \"\"\"
    try:
        if live_tty:  s.write(pty + '\\n')
        else:         ok(\"\"\"Get a PTY with ' %s  '\"\"\" % pty)
        s.interact()
    except KeyboardInterrupt:
        ok("Leaving")
    except Exception as e:
        err("Unexpected exception: %s" % e)
    return

def pwn(s):
    #
    # add your l337 stuff here
    #
    return True

if __name__ == "__main__":
    s = build_socket(HOST, PORT)
    raw_input("Attach with GDB and hit Enter ")
    if pwn(s):
        ok("Switching to interactive...")
        interact(s, False)
        ret = 0
    else:
        err("Failed to exploit")
        ret = 1

    s.close()
    exit(ret)

# auto-generated by gef
"""
