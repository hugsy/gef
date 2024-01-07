"""
trace-run command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import TMPDIR, ERROR_INACTIVE_SESSION_MESSAGE


class TraceRunCommand(RemoteGefUnitTestGeneric):
    """`trace-run` command test module"""

    def test_cmd_trace_run(self):
        gdb = self._gdb
        cmd = "trace-run"
        res = gdb.execute(cmd, to_string=True)
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE, res)

        cmd = "trace-run $pc+1"
        gdb.execute("start")
        gdb.execute(f"gef config trace-run.tracefile_prefix {TMPDIR / 'gef-trace-'}")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Tracing from", res)
