"""
`skipi` command test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH, ERROR_INACTIVE_SESSION_MESSAGE, p32, p64, u16, u32


class SkipiCommand(RemoteGefUnitTestGeneric):
    """`skipi` command test module"""

    cmd = "skipi"

    def test_cmd_nop_inactive(self):
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd}", to_string=True)
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE, res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_skipi_no_arg(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p32(0x9090FEEB))
        res = gdb.execute(self.cmd, to_string=True)
        assert res
        mem = u16(gef.memory.read(gef.arch.pc, 2))  # read 2 bytes
        self.assertEqual(0x9090, mem)  # 2 nops

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_skipi_skip_two_instructions(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p64(0x90909090FEEBFEEB))
        res = gdb.execute(f"{self.cmd} --n 2", to_string=True)
        assert res
        mem = u32(gef.memory.read(gef.arch.pc, 4))  # read 4 bytes
        self.assertEqual(0x90909090, mem)  # 4 nops

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_skipi_two_instructions_from_location(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p64(0x9090FEEBFEEBFEEB))
        res = gdb.execute(
            f"{self.cmd} $pc+2 --n 2", to_string=True  # from the second short jump
        )
        assert res
        mem = u16(gef.memory.read(gef.arch.pc, 2))  # read 2 bytes
        self.assertEqual(0x9090, mem)  # 2 nops
