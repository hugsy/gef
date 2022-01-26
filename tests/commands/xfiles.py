"""
`xfiles` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class XfilesCommand(GefUnitTestGeneric):
    """`xfiles` command test module"""


    def test_cmd_xfiles(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("xfiles"))
        res = gdb_start_silent_cmd("xfiles")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) >= 3)
