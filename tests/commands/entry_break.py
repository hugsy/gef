"""
`entry-break` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class EntryBreakCommand(RemoteGefUnitTestGeneric):
    """`entry-break` command test module"""

    def test_cmd_entry_break(self):
        gdb = self._gdb

        # run once (ok)
        res = gdb.execute("entry-break", to_string=True).strip()
        assert res.startswith("[+] Breaking at")

        # re-run while session running (nok)
        res = gdb.execute("entry-break", to_string=True).strip()
        assert "gdb is already running" in res
