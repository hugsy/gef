"""
`highlight` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import Color


class HighlightCommand(RemoteGefUnitTestGeneric):
    """`highlight` command test module"""

    def test_cmd_highlight(self):
        gdb = self._gdb

        gdb.execute("gef config context.layout stack")
        gdb.execute("gef config gef.disable_color 0")
        gdb.execute("start")

        for cmd in [
            "highlight add 41414141 yellow",
            "highlight add 42424242 blue",
            "highlight add 43434343 green",
            "highlight add 44444444 pink",
            'patch string $sp "AAAABBBBCCCCDDDD"',
            "hexdump qword $sp -s 2",
        ]:
            gdb.execute(cmd)

        res = gdb.execute("context", to_string=True)
        self.assertIn(f"{Color.YELLOW.value}41414141{Color.NORMAL.value}", res)
        self.assertIn(f"{Color.BLUE.value}42424242{Color.NORMAL.value}", res)
        self.assertIn(f"{Color.GREEN.value}43434343{Color.NORMAL.value}", res)
        self.assertIn(f"{Color.PINK.value}44444444{Color.NORMAL.value}", res)
