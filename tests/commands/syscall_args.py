"""
`syscall-args` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class SyscallArgsCommand(GefUnitTestGeneric):
    """`syscall-args` command test module"""


    cmd = "syscall-args"


    def test_cmd_syscall_args(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertNoException(res)
