"""
search_pattern command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import BIN_SH, ERROR_INACTIVE_SESSION_MESSAGE


class SearchPatternCommand(RemoteGefUnitTestGeneric):
    """`search_pattern` command test module"""

    def test_cmd_search_pattern(self):
        gdb = self._gdb
        cmd = f"grep {BIN_SH}"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute(f"grep {BIN_SH}", to_string=True)
        self.assertIn("0x", res)

    def test_cmd_search_pattern_regex(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute("set {char[6]} $sp = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x00 }")
        res = gdb.execute(
            r"search-pattern --regex $sp $sp+7 ([\\x20-\\x7E]{2,})(?=\\x00)",
            to_string=True
        )
        self.assertTrue(r"b'ABCDE'" in res)

        # this should not match because binary string is not null ended:
        res = gdb.execute("set {char[6]} $sp = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x03 }")
        gdb.execute(
            r"search-pattern --regex $sp $sp+7 ([\\x20-\\x7E]{2,})(?=\\x00)",
            to_string=True
        )
        self.assertNotIn(r"b'ABCDE'", res)
