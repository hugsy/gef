"""
`nop` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class NopCommand(GefUnitTestGeneric):
    """`nop` command test module"""


    cmd = "nop"


    def test_cmd_nop(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertNoException(res)
