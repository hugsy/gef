"""
theme command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class ThemeCommand(GefUnitTestGeneric):
    """`theme` command test module"""


    def test_cmd_theme(self):
        res = gdb_run_cmd("theme")
        self.assertNoException(res)
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
            res = gdb_run_cmd(f"theme {t}")
            self.assertNoException(res)
            self.assertNotIn("Invalid key", res, f"Invalid key '{t}'")

            # testing command setting
            v = "blue blah 10 -1 0xfff bold"
            res = gdb_run_cmd(f"theme {t} {v}")
            self.assertNoException(res)

        res = gdb_run_cmd(f"theme ___I_DONT_EXIST___")
        self.assertNoException(res)
        self.assertIn("Invalid key", res)
        return
