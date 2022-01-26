"""
search_pattern command test module
"""


from tests.utils import BIN_SH, GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class SearchPatternCommand(GefUnitTestGeneric):
    """`search_pattern` command test module"""


    def test_cmd_search_pattern(self):
        self.assertFailIfInactiveSession(gdb_run_cmd(f"grep {BIN_SH}"))
        res = gdb_start_silent_cmd(f"grep {BIN_SH}")
        self.assertNoException(res)
        self.assertIn("0x", res)
