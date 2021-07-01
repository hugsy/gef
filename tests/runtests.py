#!/usr/bin/env python3
#
# Run tests by spawning a gdb instance for every command.
#

import unittest
import subprocess

from helpers import (
    gdb_run_cmd,
    gdb_run_silent_cmd,
    gdb_start_silent_cmd,
    gdb_start_silent_cmd_last_line,
    gdb_test_python_method
) # pylint: disable=import-error


class GefUnitTestGeneric(unittest.TestCase):
    """Generic class for command testing, that defines all helpers"""

    @staticmethod
    def assertNoException(buf):
        if not ("Python Exception <" not in buf
                and "Traceback" not in buf
                and "'gdb.error'" not in buf
                and "Exception raised" not in buf
                and "failed to execute properly, reason:" not in buf):
            raise AssertionError("Detected error in gdb output")

    @staticmethod
    def assertFailIfInactiveSession(buf):
        if "No debugging session active" not in buf:
            raise AssertionError("No debugging session inactive warning")


class TestGefCommandsUnit(GefUnitTestGeneric):
    """Tests GEF GDB commands."""

    def test_cmd_canary(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("canary"))
        res = gdb_start_silent_cmd("canary", target="/tmp/canary.out")
        self.assertNoException(res)
        self.assertIn("Found AT_RANDOM at", res)
        self.assertIn("The canary of process ", res)
        return

    def test_cmd_capstone_disassemble(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("capstone-disassemble"))
        res = gdb_start_silent_cmd("capstone-disassemble")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)

        self.assertFailIfInactiveSession(gdb_run_cmd("cs --show-opcodes"))
        res = gdb_start_silent_cmd("cs --show-opcodes")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)
        # match the following pattern
        # 0x5555555546b2 897dec      <main+8>         mov    DWORD PTR [rbp-0x14], edi
        self.assertRegex(res, r"0x.{12}\s([0-9a-f]{2})+\s+.*")
        return

    def test_cmd_checksec(self):
        cmd = "checksec"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)

        target = "/tmp/checksec-no-canary.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("Canary                        : ✘", res)

        target = "/tmp/checksec-no-nx.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("NX                            : ✘", res)

        target = "/tmp/checksec-no-pie.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertIn("PIE                           : ✘", res)
        return

    def test_cmd_dereference(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("dereference"))

        res = gdb_start_silent_cmd("dereference $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 2)
        self.assertIn("$rsp", res)

        res = gdb_start_silent_cmd("dereference 0x0")
        self.assertNoException(res)
        self.assertIn("Unmapped address", res)
        return

    def test_cmd_edit_flags(self):
        # force enable flag
        res = gdb_start_silent_cmd_last_line("edit-flags +carry")
        self.assertNoException(res)
        self.assertIn("CARRY ", res)
        # force disable flag
        res = gdb_start_silent_cmd_last_line("edit-flags -carry")
        self.assertNoException(res)
        self.assertIn("carry ", res)
        # toggle flag
        res = gdb_start_silent_cmd_last_line("edit-flags ~carry")
        self.assertNoException(res)
        self.assertIn("CARRY ", res)
        return

    def test_cmd_elf_info(self):
        res = gdb_run_cmd("elf-info")
        self.assertNoException(res)
        self.assertIn("7f 45 4c 46", res)
        return

    def test_cmd_entry_break(self):
        res = gdb_run_cmd("entry-break", before=["gef config gef.disable_color 1",])
        self.assertNoException(res)
        return

    def test_cmd_format_string_helper(self):
        cmd = "format-string-helper"
        target = "/tmp/format-string-helper.out"
        res = gdb_run_cmd(cmd,
                          after=["set args testtest",
                                 "run",],
                          target=target)
        self.assertNoException(res)
        self.assertIn("Possible insecure format string:", res)
        return

    def test_cmd_functions(self):
        cmd = "functions"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("$_heap", res)
        return

    def test_cmd_got(self):
        cmd = "got"
        target = "/tmp/format-string-helper.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertIn("printf", res)
        self.assertIn("strcpy", res)

        res = gdb_start_silent_cmd("got printf", target=target)
        self.assertIn("printf", res)
        self.assertNotIn("strcpy", res)
        return

    def test_cmd_heap_arenas(self):
        cmd = "heap arenas"
        target = "/tmp/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Arena (base=", res)
        return

    def test_cmd_heap_set_arena(self):
        cmd = "heap set-arena main_arena"
        target = "/tmp/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target, after=["heap arenas",])
        self.assertNoException(res)
        self.assertIn("Arena (base=", res)
        return

    def test_cmd_heap_chunk(self):
        cmd = "heap chunk p1"
        target = "/tmp/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("NON_MAIN_ARENA flag: ", res)
        return

    def test_cmd_heap_chunks(self):
        cmd = "heap chunks"
        target = "/tmp/heap.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)
        return

    def test_cmd_heap_bins_fast(self):
        cmd = "heap bins fast"
        target = "/tmp/heap-fastbins.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Fastbins[idx=0, size=0x20]", res)
        return

    def test_cmd_heap_bins_non_main(self):
        cmd = 'python gdb.execute("heap bins fast {}".format(get_main_arena().next))'
        before = ['set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0']
        target = "/tmp/heap-non-main.out"
        res = gdb_run_silent_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn("size=0x20", res)
        return

    def test_cmd_heap_bins_tcache(self):
        cmd = "heap bins tcache"
        target = "/tmp/heap-non-main.out"
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Tcachebins[idx=0, size=0x20] count=1", res)
        return

    def test_cmd_heap_bins_tcache_all(self):
        cmd = "heap bins tcache all"
        target = "/tmp/heap-tcache.out"
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Tcachebins[idx=0, size=0x20] count=3", res)
        self.assertIn("Tcachebins[idx=1, size=0x30] count=3", res)
        return

    def test_cmd_heap_analysis(self):
        cmd = "heap-analysis-helper"
        target = "/tmp/heap-analysis.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd, after=["continue"], target=target)
        self.assertNoException(res)
        self.assertIn("Tracking", res)
        self.assertIn("correctly setup", res)
        self.assertIn("malloc(16)=", res)
        self.assertIn("calloc(32)=", res)
        addr = int(res.split("calloc(32)=")[1].split("\n")[0], 0)
        self.assertRegex(res, r"realloc\(.+, 48")
        self.assertIn("free({:#x}".format(addr), res)
        return

    def test_cmd_hexdump(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("hexdump $pc"))
        res = gdb_start_silent_cmd("hexdump qword $pc")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump dword $pc -s 1")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump word $pc -s 5 -r")
        self.assertNoException(res)
        res = gdb_start_silent_cmd("hexdump byte $sp -s 32")
        self.assertNoException(res)
        return

    def test_cmd_keystone_assemble(self):
        valid_cmds = [
            "assemble nop; xor eax, eax; syscall",
            "assemble --arch arm   --mode arm add  r0, r1, r2",
            "assemble --arch mips  --mode mips32   add $v0, 1",
            "assemble --arch sparc --mode sparc32  set 0, %o0",
            "assemble --arch arm64 --mode arm add x29, sp, 0; mov  w0, 0; ret"
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
        res = gdb_start_silent_cmd_last_line("patch byte $pc 0xcc", after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"0xcc\s*0x[^c]{2}")
        return

    def test_cmd_patch_word(self):
        res = gdb_start_silent_cmd_last_line("patch word $pc 0xcccc", after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1)0x[^c]{2}")
        return

    def test_cmd_patch_dword(self):
        res = gdb_start_silent_cmd_last_line("patch dword $pc 0xcccccccc", after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1\1\1)0x[^c]{2}")
        return

    def test_cmd_patch_qword(self):
        res = gdb_start_silent_cmd_last_line("patch qword $pc 0xcccccccccccccccc", after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1\1\1\1\1\1)0xcc")
        return

    def test_cmd_patch_qword_symbol(self):
        target = "/tmp/bss.out"
        before = gdb_run_silent_cmd("deref $sp 1", target=target)
        after = gdb_run_silent_cmd("patch qword $sp &msg", after=["deref $sp 1",], target=target)
        self.assertNoException(before)
        self.assertNoException(after)
        self.assertNotIn("Hello world!", before)
        self.assertIn("Hello world!", after)
        return

    def test_cmd_patch_string(self):
        res = gdb_start_silent_cmd_last_line("patch string $sp \"Gef!Gef!Gef!Gef!\"", after=["grep Gef!Gef!Gef!Gef!",])
        self.assertNoException(res)
        self.assertIn("Gef!Gef!Gef!Gef!", res)
        return

    def test_cmd_pattern_create(self):
        cmd = "pattern create 32"
        target = "/tmp/pattern.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("aaaabaaacaaadaaaeaaaf", res)

        cmd = "pattern create --period 8 32"
        target = "/tmp/pattern.out"
        res = gdb_run_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", res)
        return

    def test_cmd_pattern_search(self):
        cmd = "pattern search $rbp"
        target = "/tmp/pattern.out"
        res = gdb_run_cmd(cmd, before=["set args aaaabaaacaaadaaaeaaafaaagaaahaaa", "run"], target=target)
        self.assertNoException(res)
        self.assertIn("Found at offset", res)

        cmd = "pattern search --period 8 $rbp"
        target = "/tmp/pattern.out"
        res = gdb_run_cmd(cmd, before=["set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", "run"], target=target)
        self.assertNoException(res)
        self.assertIn("Found at offset", res)
        return

    def test_cmd_print_format(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("print-format"))
        res = gdb_start_silent_cmd("print-format $rsp")
        self.assertNoException(res)
        self.assertTrue("buf = [" in res)
        res = gdb_start_silent_cmd("print-format --lang js $rsp")
        self.assertNoException(res)
        self.assertTrue("var buf = [" in res)
        res = gdb_start_silent_cmd("print-format --lang iDontExist $rsp")
        self.assertNoException(res)
        self.assertTrue("Language must be in:" in res)
        return

    def test_cmd_process_status(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("process-status"))
        res = gdb_start_silent_cmd("process-status")
        self.assertNoException(res)
        self.assertIn("Process Information", res)
        self.assertIn("No child process", res)
        self.assertIn("No open connections", res)
        return

    def test_cmd_process_search(self):
        res = gdb_start_silent_cmd("process-search", target="/tmp/pattern.out", before=["set args w00tw00t", ])
        self.assertNoException(res)
        self.assertIn("/tmp/pattern.out", res)

        res = gdb_start_silent_cmd("process-search gdb.*fakefake", target="/tmp/pattern.out", before=["set args w00tw00t", ])
        self.assertNoException(res)
        self.assertIn("gdb", res)

        res = gdb_start_silent_cmd("process-search --smart-scan gdb.*fakefake", target="/tmp/pattern.out", before=["set args w00tw00t", ])
        self.assertNoException(res)
        self.assertNotIn("gdb", res)
        return

    def test_cmd_registers(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("registers"))
        res = gdb_start_silent_cmd("registers")
        self.assertNoException(res)
        self.assertIn("$rax", res)
        self.assertIn("$eflags", res)
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
        self.assertNotIn(": error:", res)
        self.assertTrue(len(res.splitlines()) > 2)
        return

    def test_cmd_scan(self):
        cmd = "scan libc stack"
        target = "/tmp/checksec-no-pie.out"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn(target, res)

        target = "/tmp/default.out"
        res = gdb_start_silent_cmd("scan binary libc", target=target)
        self.assertNoException(res)
        self.assertIn("__libc_start_main", res)

        return

    def test_cmd_search_pattern(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("grep /bin/sh"))
        res = gdb_start_silent_cmd("grep /bin/sh")
        self.assertNoException(res)
        self.assertIn("0x", res)
        return

    def test_cmd_set_permission(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("set-permission"))
        target = "/tmp/set-permission.out"

        res = gdb_start_silent_cmd("set-permission $sp", after=["vmmap",], target=target)
        self.assertNoException(res)
        line = [ l for l in res.splitlines() if "[stack]" in l ][0]
        parts = line.split()
        self.assertEqual(parts[3], "rwx")

        res = gdb_start_silent_cmd("set-permission 0x1338000", target=target)
        self.assertNoException(res)
        self.assertIn("Unmapped address", res)
        return

    def test_cmd_shellcode(self):
        res = gdb_start_silent_cmd("shellcode")
        self.assertNoException(res)
        self.assertIn("Missing sub-command (search|get)", res)
        return

    def test_cmd_shellcode_search(self):
        cmd = "shellcode search execve /bin/sh"
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("setuid(0) + execve(/bin/sh) 49 bytes", res)
        return

    def test_cmd_shellcode_get(self):
        res = gdb_start_silent_cmd("shellcode get 77")
        self.assertNoException(res)
        self.assertIn("Shellcode written to ", res)
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
        res = gdb_start_silent_cmd(cmd, before=["gef config trace-run.tracefile_prefix /tmp/gef-trace-"])
        self.assertNoException(res)
        self.assertIn("Tracing from", res)
        return

    def test_cmd_unicorn_emulate(self):
        cmd = "emu 10"
        res = gdb_run_cmd(cmd)
        self.assertFailIfInactiveSession(res)

        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("Final registers", res)
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
        self.assertIn("At least one valid address must be specified", res)

        res = gdb_start_silent_cmd("xinfo $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) >= 7)
        return

    def test_cmd_xor_memory(self):
        cmd = "xor-memory display $sp 0x10 0x41"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("Original block", res)
        self.assertIn("XOR-ed block", res)

        cmd = "xor-memory patch $sp 0x10 0x41"
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("Patching XOR-ing ", res)
        return

    def test_cmd_highlight(self):
        cmds = [
            "highlight add 41414141 yellow",
            "highlight add 42424242 blue",
            "highlight add 43434343 green",
            "highlight add 44444444 pink",
            'patch string $rsp "AAAABBBBCCCCDDDD"',
            "hexdump qword $rsp -s 2"
        ]

        res = gdb_start_silent_cmd('', after=cmds, strip_ansi=False)

        self.assertNoException(res)
        self.assertIn("\x1b[33m41414141\x1b[0m", res)
        self.assertIn("\x1b[34m42424242\x1b[0m", res)
        self.assertIn("\x1b[32m43434343\x1b[0m", res)
        self.assertIn("\x1b[35m44444444\x1b[0m", res)
        return

    def test_cmd_aliases(self):
        # test add functionality
        add_res = gdb_start_silent_cmd("aliases add alias_function_test example")
        self.assertNoException(add_res)
        # test list functionality
        list_res = gdb_start_silent_cmd("aliases ls", before=["aliases add alias_function_test example"])
        self.assertNoException(list_res)
        self.assertIn("alias_function_test", list_res)
        # test rm functionality
        rm_res = gdb_start_silent_cmd("aliases ls", before=["aliases add alias_function_test example", "aliases rm alias_function_test"])
        self.assertNoException(rm_res)
        self.assertNotIn("alias_function_test", rm_res)
        return


class TestGefFunctionsUnit(GefUnitTestGeneric):
    """Tests GEF internal functions."""

    def test_func_get_memory_alignment(self):
        res = gdb_test_python_method("get_memory_alignment(in_bits=False)")
        self.assertIn(res.splitlines()[-1], ("4", "8"))
        return

    def test_func_set_arch(self):
        res = gdb_test_python_method("current_arch.arch, current_arch.mode", before="set_arch()")
        res = (res.splitlines()[-1])
        self.assertIn("X86", res)
        return

    def test_func_which(self):
        res = gdb_test_python_method("which('gdb')")
        lines = res.splitlines()
        self.assertIn("/gdb", lines[-1])
        res = gdb_test_python_method("which('__IDontExist__')")
        self.assertIn("Missing file `__IDontExist__`", res)
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


class TestGdbFunctionsUnit(GefUnitTestGeneric):
    """Tests gdb convenience functions added by GEF."""

    def test_func_base(self):
        cmd = "x/s $_base()"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("\\177ELF", res)
        addr = res.splitlines()[-1].split()[0][:-1]

        cmd = "x/s $_base(\"libc\")"
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("\\177ELF", res)
        addr2 = res.splitlines()[-1].split()[0][:-1]
        self.assertNotEqual(addr, addr2)
        return

    def test_func_heap(self):
        cmd = "deref $_heap()"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target="/tmp/heap.out"))
        res = gdb_run_silent_cmd(cmd, target="/tmp/heap.out")
        self.assertNoException(res)
        self.assertIn("+0x0048:", res)

        cmd = "deref $_heap(0x10+0x10)"
        res = gdb_run_silent_cmd(cmd, target="/tmp/heap.out")
        self.assertNoException(res)
        self.assertIn("+0x0048:", res)
        return

    def test_func_got(self):
        cmd = "deref $_got()"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target="/tmp/heap.out"))
        res = gdb_run_silent_cmd(cmd, target="/tmp/heap.out")
        self.assertNoException(res)
        self.assertIn("malloc", res)
        return

    def test_func_bss(self):
        cmd = "deref $_bss()"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target="/tmp/bss.out"))
        res = gdb_run_silent_cmd(cmd, target="/tmp/bss.out")
        self.assertNoException(res)
        self.assertIn("Hello world!", res)
        return

    def test_func_stack(self):
        cmd = "deref $_stack()"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd))
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertRegex(res, r"\+0x0*20: *0x0000000000000000\n")
        return


class TestGefConfigUnit(GefUnitTestGeneric):
    """Test GEF configuration paramaters."""

    def test_config_show_opcodes_size(self):
        """Check opcodes are correctly shown"""
        res = gdb_run_cmd("entry-break", before=["gef config context.show_opcodes_size 4",])
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)
        # match one of the following patterns
        # 0x5555555546b2 897dec      <main+8>         mov    DWORD PTR [rbp-0x14], edi
        # 0x5555555546b5 488975e0    <main+11>        mov    QWORD PTR [rbp-0x20], rsi
        # 0x5555555546b9 488955d8    <main+15>        mov    QWORD PTR [rbp-0x28], rdx
        # 0x5555555546bd 64488b04... <main+19>        mov    rax, QWORD PTR fs:0x28
        self.assertRegex(res, r"0x.{12}\s([0-9a-f]{2}){1,4}(\.\.\.)?\s+.*")
        return


class TestNonRegressionUnit(GefUnitTestGeneric):
    """Non-regression tests."""

    def test_registers_show_registers_in_correct_order(self):
        """Ensure the registers are printed in the correct order (PR #670)."""
        cmd = "registers"
        x64_registers_in_correct_order = ["$rax", "$rbx", "$rcx", "$rdx", "$rsp", "$rbp", "$rsi", "$rdi", "$rip", "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", "$eflags", "$cs", ]
        lines = gdb_start_silent_cmd(cmd).splitlines()[-len(x64_registers_in_correct_order):]
        lines = [ line.split(' ')[0].replace(':', '') for line in lines ]
        self.assertEqual(x64_registers_in_correct_order, lines)
        return


    def test_context_correct_registers_refresh_with_frames(self):
        """Ensure registers are correctly refreshed when changing frame (PR #668)"""
        lines = gdb_run_silent_cmd("registers", after=["frame 5", "registers"], target="/tmp/nested.out").splitlines()
        rips = [ x for x in lines if x.startswith("$rip") ]
        self.assertEqual(len(rips), 2) # we must have only 2 entries
        self.assertNotEqual(rips[0], rips[1]) # they must be different
        self.assertIn("<f10", rips[0]) # the first one must be in the f10 frame
        self.assertIn("<f5", rips[1]) # the second one must be in the f5 frame
        return


def run_tests():
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=3))


if __name__ == "__main__":
    run_tests()