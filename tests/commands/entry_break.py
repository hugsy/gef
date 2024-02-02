"""
`entry-break` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class EntryBreakCommand(RemoteGefUnitTestGeneric):
    """`entry-break` command test module"""

    def test_cmd_entry_break(self):
        gdb = self._gdb

        # run once (ok)
        lines = (gdb.execute("entry-break", to_string=True) or "").strip().splitlines()

        #
        #
        # "[+] Breaking at Breaking at entry-point" might be the 1st or 2nd line (depending on whether we target
        # a PIC binary) start with
        #
        assert len(lines) >= 2
        assert any(line.startswith("[+] Breaking at entry-point") for line in lines)

        # re-run while session running (nok)
        res = (gdb.execute("entry-break", to_string=True) or "").strip()
        assert "gdb is already running" in res
