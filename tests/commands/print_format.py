"""
print-format command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE, p32


class PrintFormatCommand(RemoteGefUnitTestGeneric):
    """`print-format` command test module"""

    def test_cmd_print_format(self):
        gdb = self._gdb
        gef = self._gef

        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("print-format", to_string=True)
        )

        gdb.execute("start")

        res = gdb.execute("print-format $sp", to_string=True).strip()
        self.assertIn("buf = [", res)

        res = gdb.execute("print-format --lang js $sp", to_string=True).strip()
        self.assertIn("var buf = [", res)

        gef.memory.write(gef.arch.sp, p32(0x41414141))
        res = gdb.execute("print-format --lang hex $sp", to_string=True).strip()
        self.assertIn("41414141", res, f"{res}")

        res = gdb.execute("print-format --lang iDontExist $sp", to_string=True).strip()
        self.assertIn("Language must be in:", res)

    def test_cmd_print_format_bytearray(self):
        gdb = self._gdb
        gef = self._gef

        res = gdb.execute("start")

        gef.memory.write(gef.arch.sp, p32(0x41414141))

        res = gdb.execute("print-format --lang bytearray -l 4 $sp", to_string=True).strip()
        gef_var = res.split("$_gef")[1].split("'")[0]
        self.assertEqual(f"Saved data b'AAAA'... in '$_gef{gef_var}'", res)

        res = gdb.execute(f"p $_gef{gef_var}", to_string=True).strip()
        self.assertEqual("$1 = {0x41, 0x41, 0x41, 0x41}", res)
