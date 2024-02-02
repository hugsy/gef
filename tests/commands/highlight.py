"""
`highlight` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import Color


class HighlightCommand(RemoteGefUnitTestGeneric):
    """`highlight` command test module"""

    def test_cmd_highlight(self):
        gdb = self._gdb

        gdb.execute("start")

        gdb.execute("gef config context.layout stack")
        gdb.execute("gef config gef.disable_color 0")

        for cmd in [
            "highlight add 41414141 yellow",
            "highlight add 42424242 blue",
            "highlight add 43434343 green",
            "highlight add 44444444 pink",
            'patch string $sp "AAAABBBBCCCCDDDD"',
        ]:
            gdb.execute(cmd)

        res: str = (gdb.execute("hexdump qword $sp -s 2", to_string=True) or "").strip()
        assert f"{Color.YELLOW.value}41414141{Color.NORMAL.value}" in res
        assert f"{Color.BLUE.value}42424242{Color.NORMAL.value}" in res
        assert f"{Color.GREEN.value}43434343{Color.NORMAL.value}" in res
        assert f"{Color.PINK.value}44444444{Color.NORMAL.value}" in res
