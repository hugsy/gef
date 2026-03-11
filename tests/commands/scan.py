"""
scan command test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH, ERROR_INACTIVE_SESSION_MESSAGE, IN_GITHUB_ACTIONS, debug_target, is_glibc_ge


class ScanCommand(RemoteGefUnitTestGeneric):
    """`scan` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    @pytest.mark.skipif(ARCH == "aarch64" and IN_GITHUB_ACTIONS and is_glibc_ge(2, 41), reason=f"Skipped for {ARCH} on CI with glibc >= 2.41")
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
