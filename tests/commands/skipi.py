"""
`skipi` command test module
"""

import pytest

from tests.utils import (ARCH, GefUnitTestGeneric, debug_target, findlines,
                         gdb_run_cmd, gdb_run_silent_cmd, gdb_start_silent_cmd)


class SkipiCommand(GefUnitTestGeneric):
    """`skipi` command test module"""


    cmd = "skipi"


    def test_cmd_nop_inactive(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertFailIfInactiveSession(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_skipi_no_arg(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p32(0x9090feeb))", # 1 short jumps to pc + 2 nops
            after=(
                self.cmd,
                "pi print(gef.memory.read(gef.arch.pc, 2))", # read 2 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90", res) # 2 nops


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_skipi_skip_two_instructions(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p64(0x90909090feebfeeb))", # 2 short jumps to pc + 4 nops
            after=(
                f"{self.cmd} --n 2",
                "pi print(gef.memory.read(gef.arch.pc, 4))", # read 4 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90\x90\x90", res) # 4 nops


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_skipi_two_instructions_from_location(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p64(0x9090feebfeebfeeb))", # 2 short jumps to pc + 2 nops
            after=(
                f"{self.cmd} $pc+2 --n 2", # from the second short jump
                "pi print(gef.memory.read(gef.arch.pc, 2))", # read 2 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90", res) # 2 nops
