"""
checksec command test module
"""

from tests.utils import (
    gdb_run_cmd,
    _target,
    GefUnitTestGeneric
)


class ChecksecCommand(GefUnitTestGeneric):
    """`checksec` command test module"""

    def test_cmd_checksec(self):
        cmd = "checksec"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)

        target = _target("checksec-no-canary")
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("Canary                        : ✘", res)

        target = _target("checksec-no-nx")
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("NX                            : ✘", res)

        target = _target("checksec-no-pie")
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("PIE                           : ✘", res)
