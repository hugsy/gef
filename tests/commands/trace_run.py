"""
trace-run command test module
"""


from tests.utils import TMPDIR, GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class TraceRunCommand(GefUnitTestGeneric):
    """`trace-run` command test module"""


    def test_cmd_trace_run(self):
        cmd = "trace-run"
        res = gdb_run_cmd(cmd)
        self.assertFailIfInactiveSession(res)

        cmd = "trace-run $pc+1"
        res = gdb_start_silent_cmd(
            cmd,
            before=[f"gef config trace-run.tracefile_prefix {TMPDIR / 'gef-trace-'}"]
        )
        self.assertNoException(res)
        self.assertIn("Tracing from", res)
