"""
`nopi` command test module
"""

import pytest

from tests.utils import (ARCH, GefUnitTestGeneric, _target,
                         gdb_run_cmd, gdb_run_silent_cmd, gdb_start_silent_cmd)


class NopiCommand(GefUnitTestGeneric):
    """`nopi` command test module"""


    cmd = "nopi"


    def test_cmd_nopi_inactive(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertFailIfInactiveSession(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nopi_no_arg(self):
        
        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p32(0xfeebfeeb))", # 2 short jumps to pc
            after=(
                self.cmd,
                "pi print(gef.memory.read(gef.arch.pc, 4))", # read 4 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r'\x90\x90\xeb\xfe', res) # 2 nops + 1 short jump


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nopi_arg(self):
        
        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.sp, p64(0xfeebfeebfeebfeeb))",  # 4 short jumps to stack
            after=(
                f"{self.cmd} $sp --ni 2",
                "pi print(gef.memory.read(gef.arch.sp, 8))",  # read 8 bytes
            )
        )
        self.assertNoException(res)
        self.assertIn(r'\x90\x90\x90\x90\xeb\xfe\xeb\xfe', res) #  4 nops + 2 short jumps


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nopi_invalid_end_address(self):
        res = gdb_run_silent_cmd(
            f"{self.cmd} 0x1337000+0x1000-4 --ni 5",
            target=_target("mmap-known-address")
        )
        self.assertNoException(res)
        self.assertIn("reaching unmapped area", res)
