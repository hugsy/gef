"""
`canary` command test module
"""


from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target, p64, p32, is_64b, u32
from tests.base import RemoteGefUnitTestGeneric

class CanaryCommand(RemoteGefUnitTestGeneric):
    """`canary` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("canary")
        return super().setUp()

    def test_cmd_canary(self):
        assert ERROR_INACTIVE_SESSION_MESSAGE == self._gdb.execute("canary", to_string=True)
        self._gdb.execute("start")
        res = self._gdb.execute("canary", to_string=True)
        assert "The canary of process" in res
        assert self._gef.session.canary[0] == self._gef.session.original_canary[0]

    def test_overwrite_canary(self):
        gdb, gef = self._gdb, self._gef

        gdb.execute("start")
        _, canary_address = gef.session.canary
        if is_64b():
            gef.memory.write(canary_address, p64(0xDEADBEEF))
        else:
            gef.memory.write(canary_address, p32(0xDEADBEEF))
        res = u32(gef.memory.read(canary_address, gef.arch.ptrsize))
        assert 0xdeadbeef == res
