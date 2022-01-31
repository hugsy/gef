"""
`syscall-args` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd, _target


class SyscallArgsCommand(GefUnitTestGeneric):
    """`syscall-args` command test module"""


    def test_cmd_syscall_args(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("syscall-args"))

        res = gdb_start_silent_cmd("catch syscall openat",
                                   after=("continue", "syscall-args"),
                                   target=_target("syscall-args"),)
        self.assertNoException(res)
        self.assertIn("Detected syscall open", res)


class IsSyscallCommand(GefUnitTestGeneric):
    """`is-syscall` command test module"""


    def test_cmd_is_syscall(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("is-syscall"))

        res = gdb_start_silent_cmd("catch syscall openat",
                                   after=("continue", "is-syscall"),
                                   target=_target("syscall-args"),)
        self.assertNoException(res)
        self.assertIn("Current instruction is a syscall", res)
