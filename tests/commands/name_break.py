"""
`name-break` command test module
"""


from tests.utils import gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class NameBreakCommand(GefUnitTestGeneric):
    """`name-break` command test module"""


    def test_cmd_name_break(self):
        res = gdb_run_cmd("nb foobar *main+10")
        self.assertNoException(res)

        res = gdb_run_cmd("nb foobar *0xcafebabe")
        self.assertNoException(res)
        self.assertIn("at 0xcafebabe", res)

        res = gdb_start_silent_cmd("nb foobar")
        self.assertNoException(res)

