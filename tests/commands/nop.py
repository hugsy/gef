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
            "pi gef.memory.write(gef.arch.pc, p32(0xfeebfeeb))", # 2 short jumps to pc
            after=(
                self.cmd,
                "pi print(gef.memory.read(gef.arch.pc, 4))", # read 4 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90\xeb\xfe", res) # 2 nops + 1 short jump


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_arg(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.sp, p64(0xfeebfeebfeebfeeb))",  # 4 short jumps to stack
            after=(
                f"{self.cmd} --n 2 $sp",
                "pi print(gef.memory.read(gef.arch.sp, 8))",  # read 8 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90\x90\x90\xeb\xfe\xeb\xfe", res) #  4 nops + 2 short jumps


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_invalid_end_address(self):
        res = gdb_run_silent_cmd(
            f"{self.cmd} --n 5 0x1337000+0x1000-4",
            target=_target("mmap-known-address")
        )
        self.assertNoException(res)
        self.assertIn("reaching unmapped area", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_as_bytes_no_arg(self):
        res = gdb_start_silent_cmd(
            "pi print(f'*** *pc={u8(gef.memory.read(gef.arch.pc, 1))}')",
            after=(
                f"{self.cmd} --b",
                "pi print(f'*** *pc={u8(gef.memory.read(gef.arch.pc, 1)):#x}')",
            )
        )
        self.assertNoException(res)
        lines = findlines("*** *pc=", res)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "*** *pc=0x90")


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_as_bytes_arg(self):
        res = gdb_start_silent_cmd(
            "pi print(f'*** *sp={u32(gef.memory.read(gef.arch.sp, 4))}')",
            after=(
                f"{self.cmd} --b --n 4 $sp",
                "pi print(f'*** *sp={u32(gef.memory.read(gef.arch.sp, 4)):#x}')",
            )
        )
        self.assertNoException(res)
        lines = findlines("*** *sp=", res)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "*** *sp=0x90909090")


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_as_bytes_invalid_end_address(self):
        # Make sure we error out if writing nops into an unmapped or RO area
        res = gdb_run_silent_cmd(
            f"{self.cmd} --b --n 5 0x1337000+0x1000-4",
            target=_target("mmap-known-address")
        )
        self.assertNoException(res)
        self.assertIn("Cannot patch instruction at 0x1337ffc: reaching unmapped area", res)

        # We had an off-by-one bug where we couldn't write the last byte before
        # an unmapped area. Make sure that we can now.
        res = gdb_run_silent_cmd(
            f"{self.cmd} --b --n 4 0x1337000+0x1000-4",
            target=_target("mmap-known-address"),
            after="pi print(f'*** *mem={u32(gef.memory.read(0x1337ffc, 4)):#x}')",
        )
        self.assertNoException(res)
        self.assertNotIn("Cannot patch instruction at 0x1337ffc: reaching unmapped area", res)
        lines = findlines("*** *mem=", res)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "*** *mem=0x90909090")
