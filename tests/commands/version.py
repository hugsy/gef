"""
`version` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class VersionCommand(GefUnitTestGeneric):
    """`version` command test module"""


    cmd = "version"


    def test_cmd_version(self):
        res = gdb_run_cmd(self.cmd)
        self.assertNoException(res)
