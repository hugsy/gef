"""
`name-break` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class NameBreakCommand(RemoteGefUnitTestGeneric):
    """`name-break` command test module"""

    def test_cmd_name_break_no_args(self):
        gdb = self._gdb
        res = gdb.execute("nb", to_string=True)
        self.assertIn("Missing name", res)

    def test_cmd_name_break_no_session(self):
        gdb = self._gdb
        res = gdb.execute("nb foobar", to_string=True)
        self.assertIn("No debugging session active", res)

    def test_cmd_name_break_address(self):
        gdb = self._gdb

        # get address of main
        gdb.execute("b main")
        gdb.execute("run")

        main_address = gdb.execute("p/x $pc", to_string=True).strip().split()[-1]

        gdb.execute("delete")
        gdb.execute("stop")

        # set named breakpoint at main address
        res = gdb.execute(f"nb foobar *{main_address}", to_string=True)
        self.assertIn(f"at {main_address}", res)

        gdb.execute("run")

        # verify correct address is hit
        current_address = gdb.execute("p/x $pc", to_string=True).strip().split()[-1]
        self.assertEqual(main_address, current_address, f"Expected breakpoint at {main_address}, got {current_address}")

    def test_cmd_name_break_symbol_offset(self):
        gdb = self._gdb

        # get address of main+8
        gdb.execute("start")

        main_offset_address = gdb.execute("p/x *main+8", to_string=True).strip().split()[-1]

        # set named breakpoint at main+8 address
        res = gdb.execute(f"nb foobar *main+8", to_string=True)

        self.assertIn(f"at {main_offset_address}", res)

    def test_cmd_name_break_current_location(self):
        gdb = self._gdb

        # run until main
        gdb.execute("b main")
        gdb.execute("run")

        main_address = gdb.execute("p/x $pc", to_string=True).strip().split()[-1]

        # remove gdb breakpoint and set a named breakpoint at current location
        gdb.execute("delete")

        res = gdb.execute("nb foobar", to_string=True)

        self.assertIn(f"at {main_address}", res)

        # restart the process and ensure correct breakpoint is hit
        gdb.execute("run")

        current_address = gdb.execute("p/x $pc", to_string=True).strip().split()[-1]

        self.assertEqual(main_address, current_address, f"Expected breakpoint at {main_address}, got {current_address}")
