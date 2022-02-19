"""
`hexdump` command test module
"""


from tests.utils import gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class HexdumpCommand(GefUnitTestGeneric):
    """`hexdump` command test module"""


    def test_cmd_hexdump(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("hexdump $pc"))
        res = gdb_start_silent_cmd("hexdump qword $pc")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump dword $pc -s 1")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump word $pc -s 5 -r")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump byte $sp -s 32")
        self.assertNoException(res)



