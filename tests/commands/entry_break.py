"""
`entry-break` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class EntryBreakCommand(GefUnitTestGeneric):
    """`entry-break` command test module"""


    def test_cmd_entry_break(self):
        res = gdb_run_cmd("entry-break")
        self.assertNoException(res)

        res = gdb_run_cmd("entry-break", after=("entry-break",))
        self.assertNoException(res)
        self.assertIn("gdb is already running", res)
