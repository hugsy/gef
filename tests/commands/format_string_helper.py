"""
`format-string_helper` command test module
"""


from tests.utils import debug_target, gdb_run_cmd
from tests.utils import GefUnitTestGeneric


class FormatStringHelperCommand(GefUnitTestGeneric):
    """`format-string-helper` command test module"""


    def test_cmd_format_string_helper(self):
        cmd = "format-string-helper"
        target = debug_target("format-string-helper")
        res = gdb_run_cmd(cmd,
                          after=["set args testtest",
                                 "run",],
                          target=target)
        self.assertNoException(res)
        self.assertIn("Possible insecure format string:", res)
