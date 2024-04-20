"""
`stepover` command test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH, ERROR_INACTIVE_SESSION_MESSAGE, p32, p64, u16, u32


class Stepover(RemoteGefUnitTestGeneric):
    """`stepover` command test module"""

    cmd = "stepover"

    def test_cmd_stepover_inactive(self):
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd}", to_string=True)
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE, res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_stepover(self):
        gdb = self._gdb
        gef = self._gef

        payload = b"\xe8\x05\x00\x00\x00\x90\x90\x6a\x00\xc3\xb8\x69\x69\x69\x69\xc3"
        '''
        call movtag <- 'stepover' execution from this point
        nop <- 'stepover' should stops here and eax value should be 0x69696969
        nop
        push 0
        ret <- if something fails we want a specific crash
        movtag:
        mov eax, 0x69696969
        ret
        '''

        gdb.execute("start")
        gef.memory.write(gef.arch.pc, payload)
        res = gdb.execute(self.cmd, to_string=True)
        assert res
        mem = u16(gef.memory.read(gef.arch.pc, 2))  # read 2 bytes
        self.assertEqual(0x9090, mem)  # 2 nops
        self.assertEqual(0x69696969, gef.arch.register("$eax"))
