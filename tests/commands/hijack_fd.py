"""
`hijack_fd` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class HijackFdCommand(RemoteGefUnitTestGeneric):
    """`hijack-fd` command test module"""


    cmd = "hijack-fd"


    def test_cmd_hijack_fd(self):
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd}", to_string=True)
