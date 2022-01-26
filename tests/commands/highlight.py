"""
`highlight` command test module
"""


import pytest
from tests.utils import ARCH, GefUnitTestGeneric, gdb_start_silent_cmd


class HighlightCommand(GefUnitTestGeneric):
    """`highlight` command test module"""


    @pytest.mark.skipif(ARCH not in ["x86_64", "aarch64"], reason=f"Skipped for {ARCH}")
    def test_cmd_highlight_64bit(self):
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
        self.assertIn("\x1b[33m41414141\x1b[0m", res)
        self.assertIn("\x1b[34m42424242\x1b[0m", res)
        self.assertIn("\x1b[32m43434343\x1b[0m", res)
        self.assertIn("\x1b[35m44444444\x1b[0m", res)