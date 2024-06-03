"""
scan command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target


class ScanCommand(RemoteGefUnitTestGeneric):
    """`scan` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_cmd_scan(self):
        gdb = self._gdb
        cmd = "scan libc stack"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn(str(self._target), res)

        gdb.execute("start")
        res = gdb.execute("scan binary libc", to_string=True)
        self.assertIn("__libc_start_main", res)
