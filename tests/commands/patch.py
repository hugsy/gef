"""
patch command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target, u16, u32, u64, u8


class PatchCommand(RemoteGefUnitTestGeneric):
    """`patch` command test module"""

    def test_cmd_patch(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("patch", to_string=True)
        )

    def test_cmd_patch_byte(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gdb.execute("patch byte $pc 0xcc")
        mem = u8(gef.memory.read(gef.arch.pc, 1))
        self.assertEqual(mem, 0xCC)

    def test_cmd_patch_byte_bytearray(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gdb.execute("set $_gef69 = { 0xcc, 0xcc }")
        gdb.execute("patch byte $pc $_gef69")
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertEqual(mem, 0xCCCC)

    def test_cmd_patch_word(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gdb.execute("patch word $pc 0xcccc")
        mem = u16(gef.memory.read(gef.arch.pc, 2))
        self.assertEqual(mem, 0xCCCC)

    def test_cmd_patch_dword(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gdb.execute("patch dword $pc 0xcccccccc")
        mem = u32(gef.memory.read(gef.arch.pc, 4))
        self.assertEqual(mem, 0xCCCCCCCC)

    def test_cmd_patch_qword(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")
        gdb.execute("patch qword $pc 0xcccccccccccccccc")
        mem = u64(gef.memory.read(gef.arch.pc, 8))
        self.assertEqual(mem, 0xCCCCCCCCCCCCCCCC)

    def test_cmd_patch_string(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute('patch string $sp "Gef!Gef!Gef!Gef!"')
        res = gdb.execute("grep Gef!Gef!Gef!Gef!", to_string=True).strip()
        self.assertIn("Gef!Gef!Gef!Gef!", res)


class PatchCommandBss(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("bss")
        return super().setUp()

    def test_cmd_patch_qword_symbol(self):
        gdb = self._gdb
        gdb.execute("run")
        before = gdb.execute("deref -l 1 $sp", to_string=True)
        gdb.execute("patch qword $sp &msg")
        after = gdb.execute("deref -l 1 $sp", to_string=True)
        self.assertNotIn("Hello world!", before)
        self.assertIn("Hello world!", after)
