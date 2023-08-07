"""
`pie` command test module
"""

from tests.utils import (GefUnitTestGeneric, _target, find_symbol, gdb_run_cmd,
                         removeuntil)


class PieCommand(GefUnitTestGeneric):
    """`pie` command test module"""


    def setUp(self) -> None:
        target = _target("default")
        self.pie_offset = find_symbol(target, "main")
        self.assertGreater(self.pie_offset, 0)
        return super().setUp()


    def test_cmd_pie(self):
        res = gdb_run_cmd("pie")
        self.assertNoException(res)
        self.assertIn("pie (breakpoint|info|delete|run|attach|remote)", res)
        res = gdb_run_cmd("pie info 42")
        self.assertNoException(res)
        res = gdb_run_cmd("pie delete 42")
        self.assertNoException(res)


    def test_cmd_pie_breakpoint_check(self):
        # breakpoint at a random instruction and check
        res = gdb_run_cmd(f"pie breakpoint {self.pie_offset}", after=("pie info"))
        self.assertNoException(res)
        last_line_addr = res.splitlines()[-1].strip().split()
        self.assertEqual(last_line_addr[0], "1")
        self.assertEqual(last_line_addr[-1], hex(self.pie_offset))


    def test_cmd_pie_breakpoint_delete(self):
        res = gdb_run_cmd(f"pie breakpoint {self.pie_offset}", after=("pie delete 1", "pie info"))
        self.assertNoException(res)
        self.assertNotIn(hex(self.pie_offset), res)


    def test_cmd_pie_breakpoint_run(self):
        # breakpoint at a random instruction and run
        res = gdb_run_cmd("pie run", before=(f"pie breakpoint {self.pie_offset}",))
        self.assertNoException(res)
        # check we stopped for a breakpoint
        res = removeuntil("Name: \"default.out\", stopped ", res).splitlines()[0]
        self.assertIn("in main (), reason: BREAKPOINT", res)
        # check the mask of the breakpoint address
        address = int(res.split()[0], 16)
        self.assertEqual(address & self.pie_offset, self.pie_offset)
