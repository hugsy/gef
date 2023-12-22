"""
checksec command test module
"""

from tests.utils import (
    gdb_run_cmd,
    debug_target,
    GefUnitTestGeneric
)


class ChecksecCommand(GefUnitTestGeneric):
    """`checksec` command test module"""

    def test_cmd_checksec(self):
        cmd = "checksec"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)

        target = debug_target("checksec-no-canary")
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("Canary                        : ✘", res)

        target = debug_target("checksec-no-nx")
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("NX                            : ✘", res)

        target = debug_target("checksec-no-pie")
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("PIE                           : ✘", res)
