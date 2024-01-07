"""
`functions` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class FunctionsCommand(RemoteGefUnitTestGeneric):
    """`functions` command test module"""

    def test_cmd_functions(self):
        gdb = self._gdb
        res = gdb.execute("functions", to_string=True)
        self.assertIn("$_heap", res)
