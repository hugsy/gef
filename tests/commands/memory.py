"""
Memory commands test module
"""

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ERROR_INACTIVE_SESSION_MESSAGE,
    debug_target,
)


class MemoryCommand(RemoteGefUnitTestGeneric):
    """`memory` command testing module"""

    def setUp(self) -> None:
        self._target = debug_target("memwatch")
        return super().setUp()

    def test_cmd_memory_watch_basic(self):
        gdb = self._gdb

        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE,
            gdb.execute("memory watch $pc", to_string=True),
        )

        gdb.execute("start")

        # basic syntax checks
        gdb.execute("memory watch $pc 0x100 byte")
        gdb.execute("memory watch $pc 0x40 word")
        gdb.execute("memory watch $pc 0x30 dword")
        gdb.execute("memory watch $pc 0x20 qword")
        gdb.execute("memory watch $pc 0x8 pointers")
        gdb.execute("memory watch $pc")

    def test_cmd_memory_watch_global_variable(self):
        gdb = self._gdb

        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE,
            gdb.execute("memory unwatch $pc", to_string=True),
        )

        gdb.execute("start")

        gdb.execute("set args 0xdeadbeef")
        gdb.execute("memory watch &myglobal")
        gdb.execute("gef config context.layout memory")
        gdb.execute("run")

        res: str = gdb.execute("context", to_string=True)
        self.assertIn("deadbeef", res)
        self.assertNotIn("cafebabe", res)

        gdb.execute("continue")

        gdb.execute("set args 0xcafebabe")
        gdb.execute("memory watch &myglobal")
        gdb.execute("gef config context.layout memory")
        gdb.execute("run")

        res: str = gdb.execute("context", to_string=True)
        self.assertIn("cafebabe", res)
        self.assertNotIn("deadbeef", res)

    def test_cmd_memory_unwatch(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE,
            gdb.execute("memory unwatch $pc", to_string=True),
        )
        gdb.execute("start")
        gdb.execute("memory unwatch $pc", to_string=True)

    def test_cmd_memory_list(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("memory list", to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute("memory list", to_string=True).strip()
        assert "[+] No memory watches" == res

    def test_cmd_memory_reset(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("memory reset", to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute("memory reset", to_string=True)
