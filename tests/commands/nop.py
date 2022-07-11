"""
`nop` command test module
"""

import pytest

from tests.utils import (ARCH, GefUnitTestGeneric, _target, findlines,
                         gdb_run_cmd, gdb_run_silent_cmd, gdb_start_silent_cmd)


class NopCommand(GefUnitTestGeneric):
    """`nop` command test module"""


    cmd = "nop"


    def test_cmd_nop_inactive(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertFailIfInactiveSession(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_no_arg(self):
        res = gdb_start_silent_cmd(
            "pi print(f'*** *pc={u8(gef.memory.read(gef.arch.pc, 1))}')",
            after=(
                self.cmd,
                "pi print(f'*** *pc={u8(gef.memory.read(gef.arch.pc, 1))}')",
            )
        )
        self.assertNoException(res)
        lines = findlines("*** *pc=", res)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "*** *pc=144") # nop -> 0x90 -> 144


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_arg(self):
        res = gdb_start_silent_cmd(
            "pi print(f'*** *sp={u32(gef.memory.read(gef.arch.sp, 4))}')",
            after=(
                f"{self.cmd} $sp --nb 4",
                "pi print(f'*** *sp={u32(gef.memory.read(gef.arch.sp, 4))}')",
            )
        )
        self.assertNoException(res)
        lines = findlines("*** *sp=", res)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "*** *sp=2425393296") # 4*nop -> 0x90909090 -> 2425393296


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_invalid_end_address(self):
        res = gdb_run_silent_cmd(
            f"{self.cmd} 0x1337000+0x1000-4 --nb 5",
            target=_target("mmap-known-address")
        )
        self.assertNoException(res)
        self.assertIn("Cannot patch instruction at 0x1337ffc: reaching unmapped area", res)
