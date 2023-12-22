"""
`heap-analysis` command test module
"""


from tests.utils import debug_target, gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class HeapAnalysisCommand(GefUnitTestGeneric):
    """`heap-analysis` command test module"""


    def test_cmd_heap_analysis(self):
        cmd = "heap-analysis-helper"
        target = debug_target("heap-analysis")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd, after=["continue"], target=target)
        self.assertNoException(res)
        self.assertIn("Tracking", res)
        self.assertIn("correctly setup", res)
        self.assertIn("malloc(16)=", res)
        self.assertIn("calloc(32)=", res)
        addr = int(res.split("calloc(32)=")[1].split("\n")[0], 0)
        self.assertRegex(res, r"realloc\(.+, 48")
        self.assertIn(f"free({addr:#x}", res)
