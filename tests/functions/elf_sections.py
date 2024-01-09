"""
GDB function test module for ELF section convenience functions
"""


import pytest

from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target, is_64b
from tests.base import RemoteGefUnitTestGeneric


class ElfSectionGdbFunction(RemoteGefUnitTestGeneric):
    """GDB functions test module"""

    def test_func_base(self):
        """`$_base()` GDB function test"""
        gdb = self._gdb
        cmd = "x/s $_base()"

        with pytest.raises(Exception, match="No debugging session active"):
            gdb.execute(cmd)

        gdb.execute("start")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("\\177ELF", res)
        addr = res.splitlines()[-1].split()[0][:-1]

        cmd = 'x/s $_base("libc")'
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("\\177ELF", res)
        addr2 = res.splitlines()[-1].split()[0][:-1]
        self.assertNotEqual(addr, addr2)

    def test_func_stack(self):
        """`$_stack()` GDB function test"""
        gdb = self._gdb
        cmd = "deref $_stack()"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute(cmd, to_string=True)
        if is_64b():
            self.assertRegex(res, r"\+0x0*20: *0x0000000000000000\n")
        else:
            self.assertRegex(res, r"\+0x0.*20: *0x00000000\n")


class ElfSectionGdbFunctionBss(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("bss")
        return super().setUp()

    def test_func_bss(self):
        """`$_bss()` GDB function test"""
        gdb = self._gdb
        cmd = "deref $_bss()"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Hello world!", res)


class ElfSectionGdbFunctionHeap(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("heap")
        return super().setUp()

    def test_func_got(self):
        """`$_got()` GDB function test"""
        gdb = self._gdb
        cmd = "deref $_got()"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("malloc", res)

    def test_func_heap(self):
        """`$_heap()` GDB function test"""
        gdb = self._gdb
        cmd = "deref $_heap()"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        if is_64b():
            self.assertIn("+0x0048:", res)
        else:
            self.assertIn("+0x0024:", res)

        cmd = "deref $_heap(0x10+0x10)"
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        if is_64b():
            self.assertIn("+0x0048:", res)
        else:
            self.assertIn("+0x0024:", res)
