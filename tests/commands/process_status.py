"""
`process-status` command test module
"""


from tests.utils import gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class ProcessStatusCommand(GefUnitTestGeneric):
    """`process-status` command test module"""


    def test_cmd_process_status(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("process-status"))
        res = gdb_start_silent_cmd("process-status")
        self.assertNoException(res)
        self.assertIn("Process Information", res)
        self.assertIn("No child process", res)
        self.assertIn("No open connections", res)
