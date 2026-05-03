"""
checksec command test module
"""

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import debug_target


class ChecksecCommandNoCanary(RemoteGefUnitTestGeneric):
    """`checksec` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("checksec-no-canary")
        return super().setUp()

    def test_cmd_checksec(self):
        gdb = self._gdb
        gef = self._gef
        res = gdb.execute("checksec", to_string=True)
        assert "Canary                        : ✘" in res
        assert not gef.binary.checksec["Canary"]


class ChecksecCommandNoNx(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("checksec-no-nx")
        return super().setUp()

    def test_cmd_checksec(self):
        gdb = self._gdb
        gef = self._gef
        res = gdb.execute("checksec", to_string=True)
        assert "NX                            : ✘" in res
        assert not gef.binary.checksec["NX"]


class ChecksecCommandNoPie(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("checksec-no-pie")
        return super().setUp()

    def test_cmd_checksec(self):
        gdb = self._gdb
        gef = self._gef
        res = gdb.execute("checksec", to_string=True)
        assert "PIE                           : ✘" in res
        assert not gef.binary.checksec["PIE"]
