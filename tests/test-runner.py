#!/usr/bin/env python
#
# Run tests by spawning a gdb instance for every command.
#

from __future__ import print_function

import unittest, sys, shutil, os

from helpers import *


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

    def test_command_process_search(self):
        self.assertFailIfInactiveSession(gdb_run_command("grep /bin/sh"))
        res = gdb_start_silent_command("grep /bin/sh")
        self.assertNoException(res)
        self.assertTrue("0x" in res)
        return

    def test_command_registers(self):
        self.assertFailIfInactiveSession(gdb_run_command("registers"))
        res = gdb_start_silent_command("registers")
        self.assertNoException(res)
        self.assertTrue("$rax" in res and "$eflags" in res)
        return

    def test_command_process_status(self):
        self.assertFailIfInactiveSession(gdb_run_command("process-status"))
        res = gdb_start_silent_command("process-status")
        self.assertNoException(res)
        self.assertTrue("Process Information" in res \
                        and "No child process" in res \
                        and "No open connections" in res)
        return

    def test_command_xor_memory(self):
        cmd = "xor-memory display 0x555555774000 0x10 0x41"
        self.assertFailIfInactiveSession(gdb_run_command(cmd))
        res = gdb_start_silent_command(cmd)
        self.assertNoException(res)
        self.assertTrue("Original block" in res and "XOR-ed block" in res)

        cmd = "xor-memory patch 0x555555774000 0x10 0x41"
        res = gdb_start_silent_command(cmd)
        self.assertNoException(res)
        self.assertTrue("Patching XOR-ing 0x555555774000-0x555555774010 with '0x41'")
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

    def test_command_theme(self):
        res = gdb_run_command("theme")
        self.assertNoException(res)
        possible_themes = [
        "context_title_line"
        "dereference_base_address"
        "context_title_message"
        "disable_color"
        "dereference_code"
        "dereference_string"
        "default_title_message",
        "default_title_line"
        "dereference_register_value",
        "xinfo_title_message",
        ]
        for t in possible_themes:
            # testing command viewing
            res = gdb_run_command("theme {}".format(t))
            self.assertNoException(res)

            # testing command setting
            v = "blue blah 10 -1 0xfff bold"
            res = gdb_run_command("theme {} {}".format(t, v))
            self.assertNoException(res)
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
        self.assertTrue('X86' in res)
        return


if __name__ == "__main__":
    shutil.copy2("./gef.py", "/tmp/gef.py")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestGefCommands)
    unittest.TextTestRunner(verbosity=3).run(suite)
    os.unlink("/tmp/gef.py")
