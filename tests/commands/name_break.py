"""
`name-break` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class NameBreakCommand(RemoteGefUnitTestGeneric):
    """`name-break` command test module"""

    def test_cmd_name_break(self):
        gdb = self._gdb
        res = gdb.execute("nb foobar *main+10", to_string=True)
        res = gdb.execute("nb foobar *0xcafebabe", to_string=True)
        self.assertIn("at 0xcafebabe", res)

        res = gdb.execute("start")
        gdb.execute("nb foobar", to_string=True)
