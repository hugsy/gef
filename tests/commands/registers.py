"""
`registers` command test module
"""


import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH, ERROR_INACTIVE_SESSION_MESSAGE


class RegistersCommand(RemoteGefUnitTestGeneric):
    """`registers` command test module"""

    @pytest.mark.skipif(
        ARCH not in ["aarch64", "armv7l", "x86_64", "i686"],
        reason=f"Skipped for {ARCH}",
    )
    def test_cmd_registers(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("registers", to_string=True)
        )

        gdb.execute("start")
        res = gdb.execute("registers", to_string=True)

        if ARCH in ("aarch64"):
            self.assertIn("$x0", res)
            self.assertIn("$cpsr", res)
        elif ARCH in ("armv7l",):
            self.assertIn("$r0", res)
            self.assertIn("$lr", res)
            self.assertIn("$cpsr", res)
        elif ARCH in ("x86_64",):
            self.assertIn("$rax", res)
            self.assertIn("$eflags", res)
        elif ARCH in ("i686",):
            self.assertIn("$eax", res)
            self.assertIn("$eflags", res)
