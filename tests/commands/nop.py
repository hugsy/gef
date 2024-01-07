"""
`nop` command test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ARCH,
    ERROR_INACTIVE_SESSION_MESSAGE,
    debug_target,
    p16,
    p32,
    p64,
    u16,
    u32,
    u64,
)


class NopCommand(RemoteGefUnitTestGeneric):
    """`nop` command test module"""

    cmd = "nop"

    def test_cmd_nop_inactive(self):
        gdb = self._gdb

        res = gdb.execute(f"{self.cmd}", to_string=True)
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE, res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_no_arg(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p32(0xFEEBFEEB))
        gdb.execute(self.cmd)
        res = u32(gef.memory.read(gef.arch.pc, 4))
        self.assertEqual(0xFEEBFEEB, res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_check_b_and_n_same_time(self):
        gdb = self._gdb
        gdb.execute("start")
        res = gdb.execute(f"{self.cmd} --b --n", to_string=True).strip()
        self.assertEqual("[!] --b and --n cannot be specified at the same time.", res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_no_arg_break_instruction(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("start")
        gef.arch.nop_insn = b"\x90\x91\x92"
        gef.memory.write(gef.arch.pc, p32(0xFEEBFEEB))

        res = gdb.execute(self.cmd, to_string=True).strip()
        mem = u32(gef.memory.read(gef.arch.pc, 4))
        self.assertIn(r"will result in LAST-NOP (byte nr 0x2)", res)
        self.assertNotEqual(0xFEEB9090, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_force_arg_break_instruction(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.arch.nop_insn = b"\x90\x91\x92"
        gef.memory.write(gef.arch.pc, p32(0xFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --f", to_string=True).strip()
        mem = gef.memory.read(gef.arch.pc, 4)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x2)", res)
        self.assertEqual(0xFEEB9190, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_i_arg(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc + 1, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --i 2 $pc+1", to_string=True)
        mem = u64(gef.memory.read(gef.arch.pc + 1, 8))
        self.assertEqual(0xFEEBFEEB90909090, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_i_arg_reaching_unmapped_area(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc + 1, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(
            f"{self.cmd} --i 2000000000000000000000000000000000000 $pc+1",
            to_string=True,
        )
        mem = u64(gef.memory.read(gef.arch.pc + 1, 8))
        self.assertIn(r"reaching unmapped area", res)
        self.assertNotEqual(0xFEEBFEEB90909090, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p32(0x9191))
        res = gdb.execute(f"{self.cmd} --n", to_string=True)
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertEqual(0x9190, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_break_instruction(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p16(0xFEEB))
        res = gdb.execute(f"{self.cmd} --n", to_string=True)
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertEqual(0xFEEB, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_break_instruction_force(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p16(0xFEEB))
        res = gdb.execute(f"{self.cmd} --n --f", to_string=True)
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertEqual(0xFE90, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_arg(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --i 4 --n", to_string=True)
        mem = u64(gef.memory.read(gef.arch.pc, 8))
        self.assertEqual(0xFEEBFEEB90909090, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_arg_multibnop_breaks(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.arch.nop_insn = b"\x90\x91\x92"
        gef.memory.write(gef.arch.pc, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --n", to_string=True)
        mem = u64(gef.memory.read(gef.arch.pc, 8))
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertEqual(0xFEEBFEEBFEEBFEEB, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_nop_arg_multibnop_breaks_force(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.arch.nop_insn = b"\x90\x91\x92"
        gef.memory.write(gef.arch.pc, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --n --f", to_string=True)
        mem = u64(gef.memory.read(gef.arch.pc, 8))
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertEqual(0xFEEBFEEB929190, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p16(0x9191))
        res = gdb.execute(
            f"{self.cmd} --b",
            to_string=True,
        )
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertEqual(0x9190, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_break_instruction(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p16(0xFEEB))
        res = gdb.execute(f"{self.cmd} --b", to_string=True)
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertEqual(0xFEEB, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_break_instruction_force(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p16(0xFEEB))
        res = gdb.execute(f"{self.cmd} --b --f", to_string=True)
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertIn(r"b'\x90\xfe'", res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_arg(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.memory.write(gef.arch.pc, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --i 2 --b --f", to_string=True)
        mem = u64(gef.memory.read(gef.arch.pc, 8))
        self.assertEqual(0xFEEBFEEBFEEB9090, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_arg_nops_no_fit(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.arch.nop_insn = b"\x90\x91\x92"
        gef.memory.write(gef.arch.pc, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --i 4 --b", to_string=True)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x1)", res)
        mem = u64(gef.memory.read(gef.arch.pc, 8))
        self.assertEqual(0xFEEBFEEBFEEBFEEB, mem)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_bytes_arg_nops_no_fit_force(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gef.arch.nop_insn = b"\x90\x91\x92"
        gef.memory.write(gef.arch.pc, p64(0xFEEBFEEBFEEBFEEB))
        res = gdb.execute(f"{self.cmd} --i 5 --b --f", to_string=True)
        mem = gef.memory.read(gef.arch.pc, 8)
        self.assertIn(r"will result in LAST-NOP (byte nr 0x2)", res)
        self.assertIn(r"will result in LAST-INSTRUCTION", res)
        self.assertEqual(0xFEEBFE9190929190, mem)


class NopCommandMmapKnownAddress(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = (debug_target("mmap-known-address"),)
        return super().setUp()

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_invalid_end_address(self):
        gdb = self._gdb
        gdb.execute("run")
        res = gdb.execute(f"nop --i 5 0x1337000+0x1000-4", to_string=True)
        self.assertIn("reaching unmapped area", res)

    @pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
    def test_cmd_nop_as_bytes_invalid_end_address(self):
        gdb = self._gdb
        gef = self._gef
        # Make sure we error out if writing nops into an unmapped or RO area
        gdb.execute("run")
        res = gdb.execute(f"nop --b --i 5 0x1337000+0x1000-4", to_string=True)
        self.assertIn(
            "Cannot patch instruction at 0x1337ffc: reaching unmapped area", res
        )

        # We had an off-by-one bug where we couldn't write the last byte before
        # an unmapped area. Make sure that we can now.
        res = gdb.execute("nop --b --i 4 0x1337000+0x1000-4", to_string=True)
        self.assertNotIn(
            "Cannot patch instruction at 0x1337ffc: reaching unmapped area", res
        )
        # after="pi print(f'*** *mem={u32(gef.memory.read(0x1337ffc, 4)):#x}')",

        mem = u32(gef.memory.read(0x1337FFC, 4))
        self.assertEqual(0x90909090, mem)
        # lines = findlines("*** *mem=", res)
        # self.assertEqual(len(lines), 1)
        # self.assertEqual(lines[0], "*** *mem=0x90909090")
