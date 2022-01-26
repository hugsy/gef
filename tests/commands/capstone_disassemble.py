"""
capstone-disassemble command test module
"""

from tests.utils import (
    gdb_start_silent_cmd,
    gdb_run_silent_cmd,
    gdb_run_cmd,
    GefUnitTestGeneric
)


class CapstoneDisassembleCommand(GefUnitTestGeneric):
    """`capstone-disassemble` command test module"""


    def test_cmd_capstone_disassemble(self):
        self.assertNotIn("capstone", gdb_run_silent_cmd("gef missing"))
        self.assertFailIfInactiveSession(gdb_run_cmd("capstone-disassemble"))
        res = gdb_start_silent_cmd("capstone-disassemble")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)

        self.assertFailIfInactiveSession(gdb_run_cmd("cs --show-opcodes"))
        res = gdb_start_silent_cmd("cs --show-opcodes --length 5 $pc")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) >= 5)
        res = res[res.find("→  "):] # jump to the output buffer
        addr, opcode, symbol, *_ = [x.strip() for x in res.splitlines()[2].strip().split()]
        # match the correct output format: <addr> <opcode> [<symbol>] mnemonic [operands,]
        # gef➤  cs --show-opcodes --length 5 $pc
        # →    0xaaaaaaaaa840 80000090    <main+20>        adrp   x0, #0xaaaaaaaba000
        #      0xaaaaaaaaa844 00f047f9    <main+24>        ldr    x0, [x0, #0xfe0]
        #      0xaaaaaaaaa848 010040f9    <main+28>        ldr    x1, [x0]
        #      0xaaaaaaaaa84c e11f00f9    <main+32>        str    x1, [sp, #0x38]
        #      0xaaaaaaaaa850 010080d2    <main+36>        movz   x1, #0

        self.assertTrue(addr.startswith("0x"))
        self.assertTrue(int(addr, 16))
        self.assertTrue(int(opcode, 16))
        self.assertTrue(symbol.startswith("<") and symbol.endswith(">"))

        res = gdb_start_silent_cmd("cs --show-opcodes main")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 1)