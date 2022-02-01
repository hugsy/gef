"""
`syscall-args` command test module
"""


import pytest
from tests.utils import ARCH, GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd, _target, removeuntil


class SyscallArgsCommand(GefUnitTestGeneric):
    """`syscall-args` command test module"""


    def test_cmd_syscall_args(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("syscall-args"))

        res = gdb_start_silent_cmd("catch syscall openat",
                                   after=("continue", "syscall-args"),
                                   target=_target("syscall-args"),)
        self.assertNoException(res)
        self.assertIn("Detected syscall open", res)


@pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
class IsSyscallCommand(GefUnitTestGeneric):
    """`is-syscall` command test module"""

    def setUp(self) -> None:
        self.syscall_location = None
        res = gdb_run_cmd("disassemble openfile", target=_target("syscall-args"))
        start_str = "Dump of assembler code for function main:\n"
        end_str = "End of assembler dump."
        lines = removeuntil(start_str, res[:res.find(end_str)]).splitlines()
        for line in lines:
            parts = [x.strip() for x in line.split(maxsplit=3)]
            if ARCH == "x86_64" and parts[2] == "syscall":
                self.syscall_location = parts[1].lstrip('<').rstrip('>:')
                break
            if ARCH == "i686" and parts[2] == "int 0x80":
                self.syscall_location = parts[1].lstrip('<').rstrip('>:')
                break
        return super().setUp()


    def test_cmd_is_syscall(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("is-syscall"))
        bp_loc = f"*(openfile{self.syscall_location})"
        res = gdb_run_cmd("is-syscall", target=_target("syscall-args"),
                          before=(f"break {bp_loc}", "run"),)
        self.assertNoException(res)
        self.assertIn("Current instruction is a syscall", res)
