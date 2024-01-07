"""
`hexdump` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class HexdumpCommand(RemoteGefUnitTestGeneric):
    """`hexdump` command test module"""


    def test_cmd_hexdump(self):
        gdb = self._gdb
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE,gdb.execute("hexdump $pc", to_string=True))

        gdb.execute("start")
        res = gdb.execute("hexdump qword $pc", to_string=True)
        res = gdb.execute("hexdump dword $pc -s 1", to_string=True)
        res = gdb.execute("hexdump word $pc -s 5 -r", to_string=True)
        res = gdb.execute("hexdump byte $sp -s 32", to_string=True)
