"""
`nop` command test module
"""

import pytest

from tests.utils import (ARCH, GefUnitTestGeneric, debug_target, findlines,
                         gdb_run_cmd, gdb_run_silent_cmd, gdb_start_silent_cmd)


class NopCommand(GefUnitTestGeneric):
    """`nop` command test module"""


    cmd = "nop"


    def test_cmd_nop_inactive(self):
        res = gdb_run_cmd(f"{self.cmd}")
        self.assertFailIfInactiveSession(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_no_arg(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p32(0xfeebfeeb))",
            after=(
                self.cmd,
                "pi print(gef.memory.read(gef.arch.pc, 4))",
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90\xeb\xfe", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_check_b_and_n_same_time(self):

        res = gdb_start_silent_cmd(f"{self.cmd} --b --n")
        self.assertNoException(res)
        self.assertIn(r"--b and --n cannot be specified at the same time.", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_no_arg_break_instruction(self):
        res = gdb_start_silent_cmd(
            (r"pi gef.arch.nop_insn=b'\x90\x91\x92'",
             "pi gef.memory.write(gef.arch.pc, p32(0xfeebfeeb))"),

            after=(
                self.cmd,
                "pi print(gef.memory.read(gef.arch.pc, 4))",
            )
        )
        self.assertNoException(res)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x2)", res)
        self.assertNotIn(r"\x90\x90\xeb\xfe", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_force_arg_break_instruction(self):
        res = gdb_start_silent_cmd(
            (r"pi gef.arch.nop_insn=b'\x90\x91\x92'",
             "pi gef.memory.write(gef.arch.pc, p32(0xfeebfeeb))"),

            after=(
                f"{self.cmd} --f",
                "pi print(gef.memory.read(gef.arch.pc, 4))",
            )
        )
        self.assertNoException(res)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x2)", res)
        self.assertIn(r"\x90\x91\xeb\xfe", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_i_arg(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc+1, p64(0xfeebfeebfeebfeeb))",
            after=(
                f"{self.cmd} --i 2 $pc+1",
                "pi print(gef.memory.read(gef.arch.pc+1, 8))",
            )
        )
        self.assertNoException(res)
        self.assertIn(r"\x90\x90\x90\x90\xeb\xfe\xeb\xfe", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_i_arg_reaching_unmapped_area(self):

        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc+1, p64(0xfeebfeebfeebfeeb))",
            after=(
                f"{self.cmd} --i 2000000000000000000000000000000000000 $pc+1",
                "pi print(gef.memory.read(gef.arch.pc+1, 8))",
            )
        )
        self.assertIn(r"reaching unmapped area", res)
        self.assertNoException(res)
        self.assertNotIn(r"\x90\x90\x90\x90\xeb\xfe\xeb\xfe", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_invalid_end_address(self):
        res = gdb_run_silent_cmd(
            f"{self.cmd} --i 5 0x1337000+0x1000-4",
            target=debug_target("mmap-known-address")
        )
        self.assertNoException(res)
        self.assertIn("reaching unmapped area", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop(self):
        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p32(0x9191))",
            after=(
                f"{self.cmd} --n",
                "pi print(gef.memory.read(gef.arch.pc, 2))",
            )
        )
        self.assertIn(r"\x90\x91", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_break_instruction(self):
        res = gdb_start_silent_cmd(
           "pi gef.memory.write(gef.arch.pc, p16(0xfeeb))",
            after=(
                f"{self.cmd} --n",
                "pi print(gef.memory.read(gef.arch.pc, 2))",
            )
        )
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\xeb\xfe'", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_break_instruction_force(self):
        res = gdb_start_silent_cmd(
           "pi gef.memory.write(gef.arch.pc, p16(0xfeeb))",
            after=(
                f"{self.cmd} --n --f",
                "pi print(gef.memory.read(gef.arch.pc, 2))",
            )
        )
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\x90\xfe'", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_arg(self):
        res = gdb_start_silent_cmd(
           "pi gef.memory.write(gef.arch.pc, p64(0xfeebfeebfeebfeeb))",
            after=(
                f"{self.cmd} --i 4 --n",
                "pi print(gef.memory.read(gef.arch.pc, 8))",
            )
        )
        self.assertIn(r"b'\x90\x90\x90\x90\xeb\xfe\xeb\xfe'", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_arg_multibnop_breaks(self):
        res = gdb_start_silent_cmd(
            (r"pi gef.arch.nop_insn=b'\x90\x91\x92'",
             "pi gef.memory.write(gef.arch.pc, p64(0xfeebfeebfeebfeeb))"),

            after=(
                f"{self.cmd} --n",
                "pi print(gef.memory.read(gef.arch.pc, 8))",
            )
        )
        self.assertNoException(res)
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\xeb\xfe\xeb\xfe\xeb\xfe\xeb\xfe'", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_arg_multibnop_breaks_force(self):
        res = gdb_start_silent_cmd(
            (r"pi gef.arch.nop_insn=b'\x90\x91\x92'",
             "pi gef.memory.write(gef.arch.pc, p64(0xfeebfeebfeebfeeb))"),

            after=(
                f"{self.cmd} --n --f",
                "pi print(gef.memory.read(gef.arch.pc, 8))",
            )
        )
        self.assertNoException(res)
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\x90\x91\x92\xfe\xeb\xfe\xeb\xfe'", res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes(self):
        res = gdb_start_silent_cmd(
            "pi gef.memory.write(gef.arch.pc, p16(0x9191))",
            after=(
                f"{self.cmd} --b",
                "pi print(gef.memory.read(gef.arch.pc, 2))",
            )
        )

        self.assertIn(r"\x90\x91", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_break_instruction(self):
        res = gdb_start_silent_cmd(
           "pi gef.memory.write(gef.arch.pc, p16(0xfeeb))",
            after=(
                f"{self.cmd} --b",
                "pi print(gef.memory.read(gef.arch.pc, 2))",
            )
        )

        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\xeb\xfe'", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_break_instruction_force(self):
        res = gdb_start_silent_cmd(
           "pi gef.memory.write(gef.arch.pc, p16(0xfeeb))",
            after=(
                f"{self.cmd} --b --f",
                "pi print(gef.memory.read(gef.arch.pc, 2))",
            )
        )
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\x90\xfe'", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_arg(self):
        res = gdb_start_silent_cmd(
           "pi gef.memory.write(gef.arch.pc, p64(0xfeebfeebfeebfeeb))",
            after=(
                f"{self.cmd} --i 2 --b --f",
                "pi print(gef.memory.read(gef.arch.pc, 8))",
            )
        )
        self.assertIn(r"b'\x90\x90\xeb\xfe\xeb\xfe\xeb\xfe'", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_arg_nops_no_fit(self):
        res = gdb_start_silent_cmd(
            (r"pi gef.arch.nop_insn=b'\x90\x91\x92'",
             "pi gef.memory.write(gef.arch.pc, p64(0xfeebfeebfeebfeeb))"),

            after=(
                f"{self.cmd} --i 4 --b",
                "pi print(gef.memory.read(gef.arch.pc, 8))",
            )
        )
        self.assertIn(r"b'\xeb\xfe\xeb\xfe\xeb\xfe\xeb\xfe'", res)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x1)", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_arg_nops_no_fit_force(self):
        res = gdb_start_silent_cmd(
            (r"pi gef.arch.nop_insn=b'\x90\x91\x92'",
             "pi gef.memory.write(gef.arch.pc, p64(0xfeebfeebfeebfeeb))"),

            after=(
                f"{self.cmd} --i 5 --b --f",
                "pi print(gef.memory.read(gef.arch.pc, 8))",
            )
        )
        self.assertIn(r"b'\x90\x91\x92\x90\x91\xfe\xeb\xfe'", res)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x2)", res)
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertNoException(res)


    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_as_bytes_invalid_end_address(self):
        # Make sure we error out if writing nops into an unmapped or RO area
        res = gdb_run_silent_cmd(
            f"{self.cmd} --b --i 5 0x1337000+0x1000-4",
            target=debug_target("mmap-known-address")
        )
        self.assertNoException(res)
        self.assertIn("Cannot patch instruction at 0x1337ffc: reaching unmapped area", res)

        # We had an off-by-one bug where we couldn't write the last byte before
        # an unmapped area. Make sure that we can now.
        res = gdb_run_silent_cmd(
            f"{self.cmd} --b --i 4 0x1337000+0x1000-4",
            target=debug_target("mmap-known-address"),
            after="pi print(f'*** *mem={u32(gef.memory.read(0x1337ffc, 4)):#x}')",
        )
        self.assertNoException(res)
        self.assertNotIn("Cannot patch instruction at 0x1337ffc: reaching unmapped area", res)
        lines = findlines("*** *mem=", res)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "*** *mem=0x90909090")
