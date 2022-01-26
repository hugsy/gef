"""
vmmap command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class VmmapCommand(GefUnitTestGeneric):
    """`vmmap` command test module"""

    def test_cmd_vmmap(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("vmmap"))
        res = gdb_start_silent_cmd("vmmap")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)

        res = gdb_start_silent_cmd("vmmap stack")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)
