"""
`entry-break` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class EntryBreakCommand(GefUnitTestGeneric):
    """`entry-break` command test module"""


    def test_cmd_entry_break(self):
        res = gdb_run_cmd("entry-break")
        self.assertNoException(res)
