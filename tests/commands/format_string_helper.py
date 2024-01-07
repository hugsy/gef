"""
`format-string_helper` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import debug_target



class FormatStringHelperCommand(RemoteGefUnitTestGeneric):
    """`format-string-helper` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("format-string-helper")
        return super().setUp()

    def test_cmd_format_string_helper(self):
        gdb = self._gdb

        gdb.execute("set args testtest")
        gdb.execute("run")
        res = gdb.execute("format-string-helper", to_string=True)
        assert "Possible insecure format string:" in res
