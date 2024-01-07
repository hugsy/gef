"""
`entry-break` command test module
"""


from tests.base import RemoteGefUnitTestGeneric



class EntryBreakCommand(RemoteGefUnitTestGeneric):
    """`entry-break` command test module"""


    def test_cmd_entry_break(self):
        res = self._gdb.execute("entry-break", to_string=True).strip()
        assert "gdb is already running" in res
