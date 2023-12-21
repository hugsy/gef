"""
Memory commands test module
"""

from tests.utils import (
    GefUnitTestGeneric,
    gdb_run_cmd,
    gdb_start_silent_cmd,
    debug_target,
)


class MemoryCommand(GefUnitTestGeneric):
    """ `memory` command testing module"""


    def test_cmd_memory_watch(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("memory watch $pc"))
        res = gdb_start_silent_cmd("memory watch $pc 0x100 byte")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("memory watch $pc 0x40 word")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("memory watch $pc 0x30 dword")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("memory watch $pc 0x20 qword")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("memory watch $pc 0x8 pointers")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("memory watch $pc")
        self.assertNoException(res)
        target = debug_target("memwatch")
        res = gdb_start_silent_cmd("memory watch &myglobal",
                                   before=["set args 0xdeadbeef"],
                                   after=["continue"],
                                   target=target,
                                   context='memory')
        self.assertIn("deadbeef", res)
        self.assertNotIn("cafebabe", res)
        res = gdb_start_silent_cmd("memory watch &myglobal",
                                   before=["set args 0xcafebabe"],
                                   after=["continue"],
                                   target=target,
                                   context="memory")
        self.assertIn("cafebabe", res)
        self.assertNotIn("deadbeef", res)


    def test_cmd_memory_unwatch(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("memory unwatch $pc"))
        res = gdb_start_silent_cmd("memory unwatch $pc")
        self.assertNoException(res)


    def test_cmd_memory_list(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("memory list"))
        res = gdb_start_silent_cmd("memory list")
        self.assertNoException(res)


    def test_cmd_memory_reset(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("memory reset"))
        res = gdb_start_silent_cmd("memory reset")
        self.assertNoException(res)
