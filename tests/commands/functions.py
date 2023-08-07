"""
`functions` command test module
"""


from tests.utils import gdb_run_cmd
from tests.utils import GefUnitTestGeneric


class FunctionsCommand(GefUnitTestGeneric):
    """`functions` command test module"""


    def test_cmd_functions(self):
        cmd = "functions"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("$_heap", res)
