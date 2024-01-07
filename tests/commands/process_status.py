"""
`process-status` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class ProcessStatusCommand(RemoteGefUnitTestGeneric):
    """`process-status` command test module"""

    def test_cmd_process_status(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE,
            gdb.execute("process-status", to_string=True),
        )
        gdb.execute("start")
        res = gdb.execute("process-status", to_string=True)
        self.assertIn("Process Information", res)
        self.assertIn("No child process", res)
        self.assertIn("No open connections", res)
