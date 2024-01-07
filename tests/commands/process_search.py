"""
`process-search` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import debug_target


class ProcessSearchCommand(RemoteGefUnitTestGeneric):
    """`process-search` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("pattern")
        return super().setUp()

    def test_cmd_process_search1(self):
        gdb = self._gdb
        gdb.execute("set args w00tw00t")
        gdb.execute("start")
        res = gdb.execute("process-search", to_string=True)
        self.assertIn(str(self._target), res)

    def test_cmd_process_search_wildcart(self):
        gdb = self._gdb
        gdb.execute("set args w00tw00t")
        gdb.execute("start")
        lines = gdb.execute("process-search gdb.*fakefake", to_string=True).splitlines()
        self.assertEqual(len(lines), 0)

        lines = gdb.execute(
            f"process-search gdb.*", to_string=True
        ).splitlines()
        self.assertGreaterEqual(len(lines), 1)

    def test_cmd_process_search_smartscan(self):
        gdb = self._gdb
        gdb.execute("set args w00tw00t")
        gdb.execute("start")
        lines = gdb.execute("process-search gdb.*fakefake", to_string=True).splitlines()
        self.assertEqual(len(lines), 0)
