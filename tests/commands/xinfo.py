"""
xinfo command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target


class XinfoCommand(RemoteGefUnitTestGeneric):
    """`xinfo` command test module"""

    def test_cmd_xinfo(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("xinfo $sp", to_string=True)
        )

        gdb.execute("start")
        res = gdb.execute("xinfo", to_string=True)
        self.assertIn("At least one valid address must be specified", res)

        lines = gdb.execute("xinfo $sp", to_string=True).splitlines()
        self.assertGreaterEqual(len(lines), 6)


class XinfoCommandClass(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("class")
        return super().setUp()

    def test_cmd_xinfo_on_class(self):
        gdb = self._gdb
        cmd = "xinfo $pc+4"
        gdb.execute("b *'B<TraitA, TraitB>::Run'")
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Symbol: B<TraitA, TraitB>::Run()+4", res)
