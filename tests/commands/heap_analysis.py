"""
`heap-analysis` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target


class HeapAnalysisCommand(RemoteGefUnitTestGeneric):
    """`heap-analysis` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("heap-analysis")
        return super().setUp()

    def test_cmd_heap_analysis(self):
        gdb = self._gdb

        cmd = "heap-analysis-helper"

        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("start")
        res = gdb.execute(cmd, after=["continue"], to_string=True)
        self.assertIn("Tracking", res)
        self.assertIn("correctly setup", res)
        self.assertIn("malloc(16)=", res)
        self.assertIn("calloc(32)=", res)
        addr = int(res.split("calloc(32)=")[1].split("\n")[0], 0)
        self.assertRegex(res, r"realloc\(.+, 48")
        self.assertIn(f"free({addr:#x}", res)
