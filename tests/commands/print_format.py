"""
print-format command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class PrintFormatCommand(RemoteGefUnitTestGeneric):
    """`print-format` command test module"""

    def test_cmd_print_format(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("print-format", to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute("print-format $sp", to_string=True)
        self.assertIn("buf = [", res)
        res = gdb.execute("start")
        gdb.execute("print-format --lang js $sp", to_string=True)
        self.assertIn("var buf = [", res)
        res = gdb.execute("start")
        gdb.execute("set *((int*)$sp, to_string=True) = 0x41414141")
        res = gdb.execute("print-format --lang hex $sp", to_string=True)
        self.assertIn("41414141", res, f"{res}")
        res = gdb.execute("start")
        gdb.execute("print-format --lang iDontExist $sp", to_string=True)
        self.assertIn("Language must be in:", res)

    def test_cmd_print_format_bytearray(self):
        gdb = self._gdb
        res = gdb.execute("start")
        gdb.execute("set *((int*)$sp, to_string=True) = 0x41414141")
        res = gdb.execute("print-format --lang bytearray -l 4 $sp", to_string=True)
        gef_var = res.split("$_gef")[1].split("'")[0]
        self.assertTrue("\x41\x41\x41\x41" in res)
        res = gdb.execute("start")
        gdb.execute("set *((int*)$sp, to_string=True) = 0x41414141")
        gdb.execute("print-format --lang bytearray -l 4 $sp")
        res = gdb.execute("p $_gef" + gef_var, to_string=True)
        self.assertIn(f"Saved data b'AAAA'... in '$_gef{gef_var}'", res)
