"""
`highlight` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_start_silent_cmd, Color


class HighlightCommand(GefUnitTestGeneric):
    """`highlight` command test module"""


    def test_cmd_highlight(self):
        cmds = [
            "highlight add 41414141 yellow",
            "highlight add 42424242 blue",
            "highlight add 43434343 green",
            "highlight add 44444444 pink",
            'patch string $sp "AAAABBBBCCCCDDDD"',
            "hexdump qword $sp -s 2"
        ]

        res = gdb_start_silent_cmd('', after=cmds, strip_ansi=False)

        self.assertNoException(res)
        self.assertIn(f"{Color.YELLOW.value}41414141{Color.NORMAL.value}", res)
        self.assertIn(f"{Color.BLUE.value}42424242{Color.NORMAL.value}", res)
        self.assertIn(f"{Color.GREEN.value}43434343{Color.NORMAL.value}", res)
        self.assertIn(f"{Color.PINK.value}44444444{Color.NORMAL.value}", res)
