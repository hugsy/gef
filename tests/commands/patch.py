"""
patch command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, debug_target



class PatchCommand(RemoteGefUnitTestGeneric):
    """`patch` command test module"""


    def test_cmd_patch(self):
        gdb = self._gdb
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE,gdb.execute("patch", to_string=True))


    def test_cmd_patch_byte(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute("patch byte $pc 0xcc")
        res = gdb.execute("display/8bx $pc", to_string=True).strip()
        self.assertRegex(res, r"0xcc\s*0x[^c]{2}")

    def test_cmd_patch_byte_bytearray(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute("set $_gef69 = { 0xcc, 0xcc }")
        res = gdb.execute("patch byte $pc $_gef69", "display/8bx $pc", to_string=True).strip()
        self.assertRegex(res, r"(0xcc\s*)(\1)0x[^c]{2}")

    def test_cmd_patch_word(self):
        gdb = self._gdb
        gdb.execute("start")
        res = gdb.execute("patch word $pc 0xcccc")
        res = gdb.execute("display/8bx $pc", to_string=True).strip()
        self.assertRegex(res, r"(0xcc\s*)(\1)0x[^c]{2}")


    def test_cmd_patch_dword(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute("patch dword $pc 0xcccccccc")
        res = gdb.execute("display/8bx $pc", to_string=True).strip()
        self.assertRegex(res, r"(0xcc\s*)(\1\1\1)0x[^c]{2}")

    def test_cmd_patch_qword(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute("patch qword $pc 0xcccccccccccccccc")
        res = gdb.execute("display/8bx $pc", to_string=True).strip()
        self.assertRegex(res, r"(0xcc\s*)(\1\1\1\1\1\1)0xcc")


    def test_cmd_patch_string(self):
        gdb = self._gdb
        gdb.execute("patch string $sp \"Gef!Gef!Gef!Gef!\"")
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
