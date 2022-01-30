"""
theme command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class ThemeCommand(GefUnitTestGeneric):
    """`theme` command test module"""


    def test_cmd_theme(self):
        res = gdb_run_cmd("theme")
        self.assertNoException(res)
        possible_themes = [
            "context_title_line"
            "dereference_base_address"
            "context_title_message"
            "disable_color"
            "dereference_code"
            "dereference_string"
            "default_title_message",
            "default_title_line"
            "dereference_register_value",
            "xinfo_title_message",
        ]
        for t in possible_themes:
            # testing command viewing
            res = gdb_run_cmd(f"theme {t}")
            self.assertNoException(res)
            self.assertNotIn("Invalid key", res)

            # testing command setting
            v = "blue blah 10 -1 0xfff bold"
            res = gdb_run_cmd(f"theme {t} {v}")
            self.assertNoException(res)

        res = gdb_run_cmd(f"theme ___I_DONT_EXIST___")
        self.assertNoException(res)
        self.assertIn("Invalid key", res)
        return
