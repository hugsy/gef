"""
`pie` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class PieCommand(GefUnitTestGeneric):
    """`pie` command test module"""


    cmd = "pie"


    def test_cmd_pie(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertNoException(res)

