"""
`canary` command test module
"""


from tests.utils import ARCH, ERROR_INACTIVE_SESSION_MESSAGE, debug_target, p64
from tests.utils import RemoteGefUnitTestGeneric
import pytest

class CanaryCommand(RemoteGefUnitTestGeneric):
    """`canary` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("canary")
        return super().setUp()


    def test_cmd_canary(self):
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE, self._gdb.execute("canary", to_string=True))
        self._gdb.execute("start")
        res = self._gdb.execute("canary", to_string=True)
        self.assertIn("The canary of process", res)
        self.assertEqual(self._gef.session.canary[0], self._gef.session.original_canary[0])


    @pytest.mark.skipif(ARCH != "x86_64", reason=f"Not implemented for {ARCH}")
    def test_overwrite_canary(self):
        gdb, gef = self._gdb, self._gef

        gdb.execute("start")
        gef.memory.write(gef.arch.canary_address(), p64(0xdeadbeef))
        res = gef.memory.read(gef.arch.canary_address(), gef.arch.ptrsize)
        self.assertEqual(0xdeadbeef, res)
