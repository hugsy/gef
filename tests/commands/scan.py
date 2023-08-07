"""
scan command test module
"""


from tests.utils import GefUnitTestGeneric, _target, gdb_run_cmd, gdb_start_silent_cmd


class ScanCommand(GefUnitTestGeneric):
    """`scan` command test module"""


    def test_cmd_scan(self):
        cmd = "scan libc stack"
        target = _target("checksec-no-pie")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(str(target), res)

        res = gdb_start_silent_cmd("scan binary libc")
        self.assertNoException(res)
        self.assertIn("__libc_start_main", res)
