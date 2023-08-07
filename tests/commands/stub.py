"""
stub command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class StubCommand(GefUnitTestGeneric):
    """`stub` command test module"""


    def test_cmd_stub(self):
        # due to compiler optimizations printf might be converted to puts
        cmds = ["stub printf", "stub puts"]
        self.assertFailIfInactiveSession(gdb_run_cmd(cmds))
        res = gdb_start_silent_cmd("continue")
        self.assertNoException(res)
        self.assertIn("Hello World!", res)
        res = gdb_start_silent_cmd(cmds, after=["continue"])
        self.assertNoException(res)
        self.assertNotIn("Hello World!", res)
