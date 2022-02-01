"""
`ropper` command test module
"""


import pytest

from tests.utils import ARCH, GefUnitTestGeneric, gdb_run_cmd, gdb_run_silent_cmd


class RopperCommand(GefUnitTestGeneric):
    """`ropper` command test module"""

    def setUp(self) -> None:
        try:
            import ropper # pylint: disable=W0611
        except ImportError:
            pytest.skip("ropper not available", allow_module_level=True)
        return super().setUp()


    @pytest.mark.skipif(ARCH not in ["x86_64", "i686"], reason=f"Skipped for {ARCH}")
    def test_cmd_ropper(self):
        cmd = "ropper"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        cmd = "ropper --search \"pop %; pop %; ret\""
        res = gdb_run_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertNotIn(": error:", res)
        self.assertTrue(len(res.splitlines()) > 2)

