"""
xinfo command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd, gdb_run_silent_cmd, debug_target


class XinfoCommand(GefUnitTestGeneric):
    """`xinfo` command test module"""


    def test_cmd_xinfo(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("xinfo $sp"))
        res = gdb_start_silent_cmd("xinfo")
        self.assertIn("At least one valid address must be specified", res)

        res = gdb_start_silent_cmd("xinfo $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) >= 7)

    def test_cmd_xinfo_on_class(self):
        cmd = "xinfo $pc+4"
        target = debug_target("class")
        res = gdb_run_silent_cmd(cmd, target=target, before=["b *'B<TraitA, TraitB>::Run'"])
        self.assertNoException(res)
        self.assertIn("Symbol: B<TraitA, TraitB>::Run()+4", res)
