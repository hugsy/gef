#!/usr/bin/env python3
#
# Run tests by spawning a gdb instance for every command.
#

from __future__ import print_function

import difflib
import subprocess
import sys
import unittest

from helpers import gdb_run_cmd, \
    gdb_run_silent_cmd, \
    gdb_start_silent_cmd, \
    gdb_start_silent_cmd_last_line, \
    gdb_test_python_method



class GefUnitTestGeneric(unittest.TestCase):
    """Generic class for command testing, that defines all helpers"""

    @staticmethod
    def assertNoException(buf): #pylint: disable=invalid-name
        if not (b"Python Exception <" not in buf
                and b"Traceback" not in buf
                and b"'gdb.error'" not in buf
                and b"Exception raised" not in buf
                and b"failed to execute properly, reason:" not in buf):
            raise AssertionError("Detected error in gdb output")

    @staticmethod
    def assertFailIfInactiveSession(buf): #pylint: disable=invalid-name
        if b"No debugging session active" not in buf:
            raise AssertionError("No debugging session inactive warning")


class TestGefCommands(GefUnitTestGeneric): #pylint: disable=too-many-public-methods
    """Tests GEF GDB commands."""

    def test_cmd_canary(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("canary"))
        res = gdb_start_silent_cmd("canary", target="tests/binaries/canary.out")
        self.assertNoException(res)
        self.assertIn(b"Found AT_RANDOM at", res)
        self.assertIn(b"The canary of process ", res)
        return

    def test_cmd_capstone_disassemble(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("capstone-disassemble"))
        res = gdb_start_silent_cmd("capstone-disassemble")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)
        return

    def test_cmd_checksec(self):
        cmd = "checksec"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)

        target = "tests/binaries/checksec-no-canary.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn(b"Canary                        : No", res)

        target = "tests/binaries/checksec-no-nx.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn(b"NX                            : No", res)

        target = "tests/binaries/checksec-no-pie.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn(b"PIE                           : No", res)
        return

    def test_cmd_dereference(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("dereference"))

        res = gdb_start_silent_cmd("dereference $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 2)
        self.assertIn(b"$rsp", res)

        res = gdb_start_silent_cmd("dereference 0")
        self.assertNoException(res)
        self.assertIn(b"Unmapped address", res)
        return

    def test_cmd_edit_flags(self):
        # force enable flag
        res = gdb_start_silent_cmd_last_line("edit-flags +carry")
        self.assertNoException(res)
        self.assertIn(b"CARRY ", res)
        # force disable flag
        res = gdb_start_silent_cmd_last_line("edit-flags -carry")
        self.assertNoException(res)
        self.assertIn(b"carry ", res)
        # toggle flag
        before = gdb_start_silent_cmd_last_line("edit-flags")
        self.assertNoException(before)
        after = gdb_start_silent_cmd_last_line("edit-flags ~carry")
        self.assertNoException(after)
        s = difflib.SequenceMatcher(None, before, after)
        self.assertTrue(s.ratio() > 0.90)
        return

    def test_cmd_elf_info(self):
        res = gdb_run_cmd("elf-info")
        self.assertNoException(res)
        self.assertIn(b"7f 45 4c 46", res)
        return

    def test_cmd_entry_break(self):
        res = gdb_run_cmd("entry-break")
        self.assertNoException(res)
        return

    def test_cmd_format_string_helper(self):
        cmd = "format-string-helper"
        target = "tests/binaries/format-string-helper.out"
        res = gdb_run_cmd(cmd,
                          after=["set args testtest",
                                 "run",],
                          target=target)
        self.assertNoException(res)
        self.assertIn(b"Possible insecure format string:", res)
        return

    def test_cmd_heap_arenas(self):
        cmd = "heap arenas"
        target = "tests/binaries/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(b"Arena (base=", res)
        return

    def test_cmd_heap_set_arena(self):
        cmd = "heap set-arena main_arena"
        target = "tests/binaries/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target, after=["heap arenas",])
        self.assertNoException(res)
        self.assertIn(b"Arena (base=", res)
        return

    def test_cmd_heap_chunk(self):
        cmd = "heap chunk p1"
        target = "tests/binaries/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(b"NON_MAIN_ARENA flag: ", res)
        return

    def test_cmd_heap_chunks(self):
        cmd = "heap chunks"
        target = "tests/binaries/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(b"Chunk(addr=", res)
        self.assertIn(b"top chunk", res)
        return

    def test_cmd_heap_bins_fast(self):
        cmd = "heap bins fast"
        target = "tests/binaries/heap-fastbins.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(b"Fastbins[idx=0, size=0x10]", res)
        return

    def test_cmd_heap_analysis(self):
        cmd = "heap-analysis-helper"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        return

    def test_cmd_hexdump(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("hexdump $pc"))
        res = gdb_start_silent_cmd("hexdump qword $pc")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump dword $pc l1")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump word $pc l5 down")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump byte $sp l32")
        self.assertNoException(res)
        return

    def test_cmd_keystone_assemble(self):
        valid_cmds = [
            "assemble nop; xor eax, eax; int 0x80",
            "assemble -a arm -m arm add r0, r1, r2",
            "assemble -a mips -m mips32 add $v0, 1",
            "assemble -a sparc -m sparc32  set 0, %o0",
            "assemble -a arm64 -m little_endian add x29, sp, 0; mov  w0, 0; ret"
        ]
        for cmd in valid_cmds:
            res = gdb_start_silent_cmd(cmd)
            self.assertNoException(res)
            self.assertTrue(len(res.splitlines()) > 1)
        return

    def test_cmd_patch(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("patch"))
        return

    def test_cmd_patch_byte(self):
        before = gdb_start_silent_cmd_last_line("display/8bx $pc")
        after = gdb_start_silent_cmd_last_line("patch byte $pc 0x42", after=["display/8bx $pc",])
        self.assertNoException(after)
        r = difflib.SequenceMatcher(None, before, after).ratio()
        self.assertTrue( 0.90 < r < 1.0 )
        return

    def test_cmd_patch_word(self):
        before = gdb_start_silent_cmd_last_line("display/8bx $pc")
        after = gdb_start_silent_cmd_last_line("patch word $pc 0x4242", after=["display/8bx $pc",])
        self.assertNoException(after)
        r = difflib.SequenceMatcher(None, before, after).ratio()
        self.assertTrue( 0.90 < r < 1.0 )
        return

    def test_cmd_patch_dword(self):
        before = gdb_start_silent_cmd_last_line("display/8bx $pc")
        after = gdb_start_silent_cmd_last_line("patch dword $pc 0x42424242", after=["display/8bx $pc",])
        self.assertNoException(after)
        r = difflib.SequenceMatcher(None, before, after).ratio()
        # print(r)
        self.assertTrue( 0.75 < r < 0.95 )
        return

    def test_cmd_patch_qword(self):
        before = gdb_start_silent_cmd_last_line("display/8bx $pc")
        after = gdb_start_silent_cmd_last_line("patch qword $pc 0x4242424242424242", after=["display/8bx $pc",])
        self.assertNoException(after)
        r = difflib.SequenceMatcher(None, before, after).ratio()
        self.assertTrue( r > 0.50 )
        return

    def test_cmd_patch_string(self):
        res = gdb_start_silent_cmd_last_line("patch string $sp \"Gef!Gef!Gef!Gef!\"", after=["grep Gef!Gef!Gef!Gef!",])
        self.assertNoException(res)
        self.assertIn(b"Gef!Gef!Gef!Gef!", res)
        return

    def test_cmd_pattern(self):
        cmd = "pattern create 32"
        target = "tests/binaries/pattern.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", res)

        cmd = "pattern search $rbp"
        target = "tests/binaries/pattern.out"
        res = gdb_run_cmd(cmd, before=["set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", "run"], target=target)
        self.assertNoException(res)
        self.assertIn(b"Found at offset", res)
        return

    def test_cmd_print_format(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("print-format"))
        res = gdb_start_silent_cmd("print-format $rsp")
        self.assertNoException(res)
        self.assertTrue(b"buf = [" in res)
        res = gdb_start_silent_cmd("print-format -f js $rsp")
        self.assertNoException(res)
        self.assertTrue(b"var buf = [" in res)
        res = gdb_start_silent_cmd("print-format -f iDontExist $rsp")
        self.assertNoException(res)
        self.assertTrue(b"Language must be :" in res)
        return

    def test_cmd_process_status(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("process-status"))
        res = gdb_start_silent_cmd("process-status")
        self.assertNoException(res)
        self.assertIn(b"Process Information", res)
        self.assertIn(b"No child process", res)
        self.assertIn(b"No open connections", res)
        return

    def test_cmd_registers(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("registers"))
        res = gdb_start_silent_cmd("registers")
        self.assertNoException(res)
        self.assertIn(b"$rax", res)
        self.assertIn(b"$eflags", res)
        return

    def test_cmd_reset_cache(self):
        res = gdb_start_silent_cmd("reset-cache")
        self.assertNoException(res)
        return

    def test_cmd_ropper(self):
        cmd = "ropper"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        cmd = "ropper --search \"pop %; pop %; ret\""
        res = gdb_run_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertNotIn(b": error:", res)
        self.assertTrue(len(res.splitlines()) > 2)
        return

    def test_cmd_search_pattern(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("grep /bin/sh"))
        res = gdb_start_silent_cmd("grep /bin/sh")
        self.assertNoException(res)
        self.assertIn(b"0x", res)
        return

    def test_cmd_set_permission(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("set-permission"))
        target = "tests/binaries/set-permission.out"

        res = gdb_run_silent_cmd("set-permission 0x1337000", after=["vmmap",], target=target)
        self.assertNoException(res)
        line = [ l for l in res.splitlines() if b"0x0000000001337000" in l ][0]
        line = line.split()
        self.assertEqual(line[0], b"0x0000000001337000")
        self.assertEqual(line[1], b"0x0000000001338000")
        self.assertEqual(line[2], b"0x0000000000000000")
        self.assertEqual(line[3], b"rwx")

        res = gdb_run_silent_cmd("set-permission 0x1338000", target=target)
        self.assertNoException(res)
        self.assertIn(b"Unmapped address", res)
        return

    def test_cmd_shellcode(self):
        res = gdb_start_silent_cmd("shellcode")
        self.assertNoException(res)
        self.assertIn(b"Missing sub-command <search|get>", res)
        return

    def test_cmd_shellcode_search(self):
        cmd = "shellcode search execve /bin/sh"
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn(b"setuid(0) + execve(/bin/sh) 49 bytes", res)
        return

    def test_cmd_shellcode_get(self):
        res = gdb_start_silent_cmd("shellcode get 77")
        self.assertNoException(res)
        self.assertIn(b"Shellcode written to ", res)
        return

    def test_cmd_stub(self):
        cmd = "stub printf"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        return

    def test_cmd_theme(self):
        res = gdb_run_cmd("theme")
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
            res = gdb_run_cmd("theme {}".format(t))
            self.assertNoException(res)

            # testing command setting
            v = "blue blah 10 -1 0xfff bold"
            res = gdb_run_cmd("theme {} {}".format(t, v))
            self.assertNoException(res)
        return

    def test_cmd_trace_run(self):
        cmd = "trace-run"
        res = gdb_run_cmd(cmd)
        self.assertFailIfInactiveSession(res)

        cmd = "trace-run $pc+1"
        res = gdb_start_silent_cmd(cmd,
                                   before=["gef config trace-run.tracefile_prefix /tmp/gef-trace-"])
        self.assertNoException(res)
        self.assertIn(b"Tracing from", res)
        return

    def test_cmd_unicorn_emulate(self):
        cmd = "emu -n 1"
        res = gdb_run_cmd(cmd)
        self.assertFailIfInactiveSession(res)

        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn(b"Final registers", res)
        return

    def test_cmd_vmmap(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("vmmap"))
        res = gdb_start_silent_cmd("vmmap")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)

        res = gdb_start_silent_cmd("vmmap stack")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)
        return

    def test_cmd_xfiles(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("xfiles"))
        res = gdb_start_silent_cmd("xfiles")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) >= 3)
        return

    def test_cmd_xinfo(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("xinfo $sp"))
        res = gdb_start_silent_cmd("xinfo")
        self.assertIn(b"At least one valid address must be specified", res)

        res = gdb_start_silent_cmd("xinfo $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) >= 7)
        return

    def test_cmd_xor_memory(self):
        cmd = "xor-memory display $sp 0x10 0x41"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn(b"Original block", res)
        self.assertIn(b"XOR-ed block", res)

        cmd = "xor-memory patch $sp 0x10 0x41"
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn(b"Patching XOR-ing ", res)
        return

class TestGefFunctions(GefUnitTestGeneric):
    """Tests GEF internal functions."""

    def test_func_get_memory_alignment(self):
        res = gdb_test_python_method("get_memory_alignment(in_bits=False)")
        self.assertIn(res.splitlines()[-1], (b"4", b"8"))
        return

    def test_func_set_arch(self):
        res = gdb_test_python_method("current_arch.arch, current_arch.mode", before="set_arch()")
        res = (res.splitlines()[-1])
        self.assertIn(b"X86", res)
        return

    def test_func_which(self):
        res = gdb_test_python_method("which('gdb')")
        lines = res.splitlines()
        self.assertIn(b"/gdb", lines[-1])
        res = gdb_test_python_method("which('__IDontExist__')")
        self.assertIn(b"Missing file `__IDontExist__`", res)
        return

    def test_func_get_filepath(self):
        res = gdb_test_python_method("get_filepath()", target="/bin/ls")
        self.assertNoException(res)
        subprocess.call(["cp", "/bin/ls", "/tmp/foo bar"])
        res = gdb_test_python_method("get_filepath()", target="/tmp/foo bar")
        self.assertNoException(res)
        subprocess.call(["rm", "/tmp/foo bar"])
        return

    def test_func_get_pid(self):
        res = gdb_test_python_method("get_pid()", target="/bin/ls")
        self.assertNoException(res)
        self.assertTrue(int(res.splitlines()[-1]))
        return


def run_tests():
    test_instances = [
        TestGefCommands,
        TestGefFunctions,
    ]

    runner = unittest.TextTestRunner(verbosity=3)
    total_failures = 0

    for test in [unittest.TestLoader().loadTestsFromTestCase(x) for x in test_instances]:
        res = runner.run(test)
        total_failures += len(res.errors) + len(res.failures)

    return total_failures


if __name__ == "__main__":
    sys.exit(run_tests())
