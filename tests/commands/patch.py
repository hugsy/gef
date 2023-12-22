"""
patch command test module
"""


from tests.utils import debug_target, gdb_run_cmd, gdb_run_silent_cmd, gdb_start_silent_cmd_last_line
from tests.utils import GefUnitTestGeneric


class PatchCommand(GefUnitTestGeneric):
    """`patch` command test module"""


    def test_cmd_patch(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("patch"))


    def test_cmd_patch_byte(self):
        res = gdb_start_silent_cmd_last_line("patch byte $pc 0xcc", after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"0xcc\s*0x[^c]{2}")

    def test_cmd_patch_byte_bytearray(self):
        res = gdb_start_silent_cmd_last_line("set $_gef69 = { 0xcc, 0xcc }", after=["patch byte $pc $_gef69", "display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1)0x[^c]{2}")

    def test_cmd_patch_word(self):
        res = gdb_start_silent_cmd_last_line("patch word $pc 0xcccc", after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1)0x[^c]{2}")


    def test_cmd_patch_dword(self):
        res = gdb_start_silent_cmd_last_line("patch dword $pc 0xcccccccc",
                                             after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1\1\1)0x[^c]{2}")


    def test_cmd_patch_qword(self):
        res = gdb_start_silent_cmd_last_line("patch qword $pc 0xcccccccccccccccc",
                                             after=["display/8bx $pc",])
        self.assertNoException(res)
        self.assertRegex(res, r"(0xcc\s*)(\1\1\1\1\1\1)0xcc")


    def test_cmd_patch_qword_symbol(self):
        target = debug_target("bss")
        before = gdb_run_silent_cmd("deref -l 1 $sp", target=target)
        after = gdb_run_silent_cmd("patch qword $sp &msg", after=["deref -l 1 $sp"], target=target)
        self.assertNoException(before)
        self.assertNoException(after)
        self.assertNotIn("Hello world!", before)
        self.assertIn("Hello world!", after)


    def test_cmd_patch_string(self):
        res = gdb_start_silent_cmd_last_line("patch string $sp \"Gef!Gef!Gef!Gef!\"",
                                             after=["grep Gef!Gef!Gef!Gef!",])
        self.assertNoException(res)
        self.assertIn("Gef!Gef!Gef!Gef!", res)
