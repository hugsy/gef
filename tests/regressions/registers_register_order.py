import pytest

from tests.utils import (
    GefUnitTestGeneric,
    gdb_start_silent_cmd,
    gdb_run_silent_cmd,
    debug_target,
    ARCH
)


class RegressionRegisterOrder(GefUnitTestGeneric):
    """Tests for regression in the order registers are displayed by `registers` ."""

    @pytest.mark.skipif(ARCH not in ["x86_64", "i686"], reason=f"Skipped for {ARCH}")
    def test_registers_show_registers_in_correct_order(self):
        """Ensure the registers are printed in the correct order (PR #670)."""
        cmd = "registers"
        if ARCH == "i686":
            registers_in_correct_order = ["$eax", "$ebx", "$ecx", "$edx", "$esp", "$ebp", "$esi",
                                          "$edi", "$eip", "$eflags", "$cs"]
        elif ARCH == "x86_64":
            registers_in_correct_order = ["$rax", "$rbx", "$rcx", "$rdx", "$rsp", "$rbp", "$rsi",
                                          "$rdi", "$rip", "$r8", "$r9", "$r10", "$r11", "$r12",
                                          "$r13", "$r14", "$r15", "$eflags", "$cs"]
        else:
            raise ValueError("Unknown architecture")
        lines = gdb_start_silent_cmd(cmd).splitlines()[-len(registers_in_correct_order):]
        lines = [line.split()[0].replace(':', '') for line in lines]
        self.assertEqual(registers_in_correct_order, lines)


    @pytest.mark.skipif(ARCH not in ["x86_64",], reason=f"Skipped for {ARCH}")
    def test_context_correct_registers_refresh_with_frames(self):
        """Ensure registers are correctly refreshed when changing frame (PR #668)"""
        target = debug_target("nested")
        lines = gdb_run_silent_cmd("registers", after=["frame 5", "registers"],
                                   target=target).splitlines()
        rips = [x for x in lines if x.startswith("$rip")]
        self.assertEqual(len(rips), 2) # we must have only 2 entries
        self.assertNotEqual(rips[0], rips[1]) # they must be different
        self.assertIn("<f10", rips[0]) # the first one must be in the f10 frame
        self.assertIn("<f5", rips[1]) # the second one must be in the f5 frame
