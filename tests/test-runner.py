#!/usr/bin/env python
#
# Run tests by spawning a gdb instance for every command.
#

from __future__ import print_function

import subprocess
import unittest


def gdb_run_command(cmd, before=[], after=[]):
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = ["gdb", "-q", "-ex", "gef config gef.debug True"]

    if len(before):
        for _ in before: command+= ["-ex", _]

    command += ["-ex", cmd]

    if len(after):
        for _ in after: command+= ["-ex", _]

    command+= ["-ex", "quit", "--", "/bin/ls"]
    # print("Running '{}'".format(" ".join(command)))
    lines = subprocess.check_output(command, stderr=subprocess.STDOUT).strip().splitlines()
    return "\n".join(lines[5:])


def gdb_run_command_last_line(cmd, before=[], after=[]):
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_command(cmd, before, after).splitlines()[-1]


def gdb_start_silent_command(cmd, before=[], after=[]):
    """Execute a command in GDB by starting an execution context. This command disables the `context`
    and set a tbreak at the most convenient entry point."""
    before += ["gef config context.clear_screen False",
               "gef config context.layout ''",
               "entry-break"]
    return gdb_run_command(cmd, before, after)


def gdb_start_silent_command_last_line(cmd, before=[], after=[]):
    """Execute `gdb_start_silent_command()` and return only the last line of its output."""
    before += ["gef config context.clear_screen False",
               "gef config context.layout ''",
               "entry-break"]
    return gdb_start_silent_command(cmd, before, after).splitlines()[-1]


def gdb_test_python_method(meth, before="", after=""):
    cmd = "pi {}print({});{}".format(before+";" if len(before)>0 else "", meth, after)
    return gdb_start_silent_command(cmd)


class TestGefCommands(unittest.TestCase):
    """Global class for command testing"""

    ### unittest helpers

    def assertNoException(self, buf):
        return "Python Exception <" not in buf or "'gdb.error'" in buf

    def assertFailIfInactiveSession(self, buf):
        return "No debugging session active" in buf


    ### testing GEF commands

    def test_command_entry_break(self):
        res = gdb_run_command("entry-break")
        self.assertNoException(res)
        return

    def test_command_hexdump(self):
        self.assertFailIfInactiveSession(gdb_run_command("hexdump $pc"))
        res = gdb_start_silent_command("hexdump qword $pc")
        self.assertNoException(res)
        res = gdb_start_silent_command("hexdump dword $pc l1")
        self.assertNoException(res)
        res = gdb_start_silent_command("hexdump word $pc l5 down")
        self.assertNoException(res)
        res = gdb_start_silent_command("hexdump byte $sp l32")
        self.assertNoException(res)
        return

    def test_command_vmmap(self):
        self.assertFailIfInactiveSession(gdb_run_command("vmmap"))
        res = gdb_start_silent_command("vmmap")
        self.assertNoException(res)
        self.assertTrue(res.splitlines() > 1)
        return

    def test_command_xinfo(self):
        self.assertFailIfInactiveSession(gdb_run_command("xinfo $sp"))
        res = gdb_start_silent_command("xinfo")
        self.assertTrue("At least one valid address must be specified" in res)
        res = gdb_start_silent_command("xinfo $sp")
        self.assertNoException(res)
        self.assertTrue(res.splitlines() >= 7)
        return

    def test_command_elf_info(self):
        res = gdb_run_command("elf-info")
        self.assertNoException(res)
        self.assertTrue("7f 45 4c 46" in res)
        return

    def test_command_checksec(self):
        res = gdb_run_command("checksec")
        self.assertNoException(res)
        # todo: add more granular tests (with specific binaries (no canary, no pic, etc.))
        return

    def test_command_pattern_create(self):
        res = gdb_run_command("pattern create 16")
        self.assertNoException(res)
        self.assertTrue("aaaabaaacaaadaaa" in res)
        return


    ### testing GEF methods
    def test_which(self):
        res = gdb_test_python_method("which('gdb')")
        self.assertTrue(res.splitlines()[-1].startswith("/"))
        res = gdb_test_python_method("which('__IDontExist__')")
        self.assertTrue("Missing file `__IDontExist__`" in res)
        return

    def test_get_memory_alignment(self):
        res = gdb_test_python_method("get_memory_alignment(in_bits=False)")
        self.assertTrue(res.splitlines()[-1] in ("4", "8"))
        return

    def test_set_arch(self):
        res = gdb_test_python_method("current_arch.arch, current_arch.mode", before="set_arch()")
        res = (res.splitlines()[-1])
        self.assertTrue(res.startswith("('X86',"))
        return


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestGefCommands)
    unittest.TextTestRunner(verbosity=2).run(suite)
