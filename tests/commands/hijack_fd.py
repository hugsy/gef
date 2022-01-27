"""
`hijack_fd` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class HijackFdCommand(GefUnitTestGeneric):
    """`hijack-fd` command test module"""


    cmd = "hijack-fd"


    def test_cmd_hijack_fd(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertNoException(res)
