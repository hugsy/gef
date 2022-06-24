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
        self.assertTrue("buf = [" in res)
        res = gdb_start_silent_cmd("print-format --lang js $sp")
        self.assertNoException(res)
        self.assertTrue("var buf = [" in res)
        res = gdb_start_silent_cmd("set *((int*)$sp) = 0x41414141",
                                   after=["print-format --lang hex $sp"])
        self.assertNoException(res)
        self.assertTrue("41414141" in res, f"{res}")
        res = gdb_start_silent_cmd("print-format --lang iDontExist $sp")
        self.assertNoException(res)
        self.assertTrue("Language must be in:" in res)


    def test_cmd_print_format_bytearray(self):
        res = gdb_start_silent_cmd("set *((int*)$sp) = 0x41414141",
                                   after=["print-format --lang bytearray -l 4 $sp"])
        self.assertNoException(res)
        try:
            gef_var = res.split('$_gef')[1].split("'")[0]
        except:
            self.assertTrue(False)
        self.assertTrue("\x41\x41\x41\x41" in res)
        res = gdb_start_silent_cmd("set *((int*)$sp) = 0x41414141",
                                   after=["print-format --lang bytearray -l 4 $sp", "p $_gef" + gef_var])
        self.assertNoException(res)
        self.assertTrue("0x41, 0x41, 0x41, 0x41" in res)
