"""
print-format command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class PrintFormatCommand(GefUnitTestGeneric):
    """`print-format` command test module"""


    def test_cmd_print_format(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("print-format"))
        res = gdb_start_silent_cmd("print-format $sp")
        self.assertNoException(res)
        self.assertIn("buf = [" , res)
        res = gdb_start_silent_cmd("print-format --lang js $sp")
        self.assertNoException(res)
        self.assertIn("var buf = [" , res)
        res = gdb_start_silent_cmd("set *((int*)$sp) = 0x41414141",
                                   after=["print-format --lang hex $sp"])
        self.assertNoException(res)
        self.assertIn("41414141", res, f"{res}")
        res = gdb_start_silent_cmd("print-format --lang iDontExist $sp")
        self.assertNoException(res)
        self.assertIn("Language must be in:" , res)


    def test_cmd_print_format_bytearray(self):
        res = gdb_start_silent_cmd("set *((int*)$sp) = 0x41414141",
                                   after=["print-format --lang bytearray -l 4 $sp"])
        self.assertNoException(res)
        gef_var = res.split('$_gef')[1].split("'")[0]
        self.assertTrue("\x41\x41\x41\x41" in res)
        res = gdb_start_silent_cmd("set *((int*)$sp) = 0x41414141",
                                   after=["print-format --lang bytearray -l 4 $sp", "p $_gef" + gef_var])
        self.assertNoException(res)
        self.assertIn(
            f"Saved data b'AAAA'... in '$_gef{gef_var}'", res)
