"""
`registers` command test module
"""


import pytest
from tests.utils import ARCH, GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class RegistersCommand(GefUnitTestGeneric):
    """`registers` command test module"""


    @pytest.mark.skipif(ARCH not in ["aarch64", "armv7l", "x86_64", "i686"],
                        reason=f"Skipped for {ARCH}")
    def test_cmd_registers(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("registers"))
        res = gdb_start_silent_cmd("registers")
        self.assertNoException(res)
        if ARCH in ("aarch64",):
            self.assertIn("$x0", res)
            self.assertIn("$cpsr", res)
        elif ARCH in ("armv7l", ):
            self.assertIn("$r0", res)
            self.assertIn("$lr", res)
            self.assertIn("$cpsr", res)
        elif ARCH in ("x86_64", ):
            self.assertIn("$rax", res)
            self.assertIn("$eflags", res)
        elif ARCH in ("i686", ):
            self.assertIn("$eax", res)
            self.assertIn("$eflags", res)
