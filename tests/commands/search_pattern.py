"""
search_pattern command test module
"""


from tests.utils import BIN_SH, GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd, gdb_start_silent_cmd_last_line


class SearchPatternCommand(GefUnitTestGeneric):
    """`search_pattern` command test module"""


    def test_cmd_search_pattern(self):
        self.assertFailIfInactiveSession(gdb_run_cmd(f"grep {BIN_SH}"))
        res = gdb_start_silent_cmd(f"grep {BIN_SH}")
        self.assertNoException(res)
        self.assertIn("0x", res)

    def test_cmd_search_pattern_regex(self):
        res = gdb_start_silent_cmd_last_line("set {char[6]} $sp = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x00 }", 
after=[r"search-pattern --regex $sp $sp+7 ([\\x20-\\x7E]{2,})(?=\\x00)",])
        self.assertNoException(res)
        self.assertTrue(r"b'ABCDE'" in res)
        # this should not match because binary string is not null ended:
        res = gdb_start_silent_cmd_last_line("set {char[6]} $sp = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x03 }", 
after=[r"search-pattern --regex $sp $sp+7 ([\\x20-\\x7E]{2,})(?=\\x00)",])
        self.assertNoException(res)
        self.assertTrue(r"b'ABCDE'" not in res)


