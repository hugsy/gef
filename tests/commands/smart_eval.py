"""
`smart_eval` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class SmartEvalCommand(GefUnitTestGeneric):
    """`smart_eval` command test module"""


    cmd = "$"


    def test_cmd_smart_eval(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertNoException(res)
