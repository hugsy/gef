"""
`version` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class VersionCommand(RemoteGefUnitTestGeneric):
    """`version` command test module"""

    cmd = "version"

    def test_cmd_version(self):
        gdb = self._gdb
        gdb.execute(self.cmd)
