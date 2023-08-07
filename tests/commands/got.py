"""
`got` command test module
"""

import pytest

from tests.utils import (
    ARCH,
    _target,
    gdb_run_cmd,
    gdb_start_silent_cmd,
    GefUnitTestGeneric,
)


@pytest.mark.skipif(ARCH in ("ppc64le",), reason=f"Skipped for {ARCH}")
class GotCommand(GefUnitTestGeneric):
    """`got` command test module"""


    def test_cmd_got(self):
        cmd = "got"
        target = _target("format-string-helper")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertIn("printf", res)
        self.assertIn("strcpy", res)

        res = gdb_start_silent_cmd("got printf", target=target)
        self.assertIn("printf", res)
        self.assertNotIn("strcpy", res)
