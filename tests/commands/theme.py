"""
theme command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class ThemeCommand(RemoteGefUnitTestGeneric):
    """`theme` command test module"""

    def test_cmd_theme(self):
        gdb = self._gdb
        res = gdb.execute("theme", to_string=True)
        possible_themes = (
            "context_title_line",
            "context_title_message",
            "default_title_line",
            "default_title_message",
            "table_heading",
            "old_context",
            "disassemble_current_instruction",
            "dereference_string",
            "dereference_code",
            "dereference_base_address",
            "dereference_register_value",
            "registers_register_name",
            "registers_value_changed",
            "address_stack",
            "address_heap",
            "address_code",
            "source_current_line",
        )
        for t in possible_themes:
            # testing command viewing
            res = gdb.execute(f"theme {t}", to_string=True)
            self.assertNotIn("Invalid key", res, f"Invalid key '{t}'")

            # testing command setting
            v = "blue blah 10 -1 0xfff bold"
            gdb.execute(f"theme {t} {v}")


        res = gdb.execute(f"theme ___I_DONT_EXIST___", to_string=True)
        self.assertIn("Invalid key", res)
