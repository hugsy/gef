"""
`pie` command test module
"""

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import debug_target, find_symbol, removeuntil


class PieCommand(RemoteGefUnitTestGeneric):
    """`pie` command test module"""

    def setUp(self) -> None:
        target = debug_target("default")
        self.pie_offset = find_symbol(target, "main")
        self.assertGreater(self.pie_offset, 0)
        return super().setUp()

    def test_cmd_pie(self):
        gdb = self._gdb
        res = gdb.execute("pie", to_string=True)
        self.assertIn("pie (breakpoint|info|delete|run|attach|remote)", res)
        gdb.execute("pie info 42")
        res = gdb.execute("pie delete 42", to_string=True).strip()
        assert not res

    def test_cmd_pie_breakpoint_check(self):
        gdb = self._gdb

        # breakpoint at a random instruction and check
        gdb.execute(f"pie breakpoint {self.pie_offset}")
        res = gdb.execute("pie info", to_string=True)
        last_line_addr = res.splitlines()[-1].strip().split()
        self.assertEqual(last_line_addr[0], "1")
        self.assertEqual(last_line_addr[-1], hex(self.pie_offset))

    def test_cmd_pie_breakpoint_delete(self):
        gdb = self._gdb
        gdb.execute(f"pie breakpoint {self.pie_offset}")
        gdb.execute("pie delete 1")
        res = gdb.execute("pie info", to_string=True)
        self.assertNotIn(hex(self.pie_offset), res)

    def test_cmd_pie_breakpoint_run(self):
        gdb = self._gdb
        # breakpoint at a random instruction and run
        gdb.execute(f"pie breakpoint {self.pie_offset}")
        res = gdb.execute(
            "pie run",
            to_string=True
        )
        # check we stopped for a breakpoint
        res = removeuntil('Name: "default.out", stopped ', res).splitlines()[0]
        self.assertIn("in main (), reason: BREAKPOINT", res)
        # check the mask of the breakpoint address
        address = int(res.split()[0], 16)
        self.assertEqual(address & self.pie_offset, self.pie_offset)
