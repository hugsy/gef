"""
Tests GEF internal functions.
"""


from tests.utils import BIN_LS, gdb_test_python_method, start_gdbserver, stop_gdbserver
from tests.utils import GefUnitTestGeneric


class MiscFunctionTest(GefUnitTestGeneric):
    """Tests GEF internal functions."""


    def test_func_which(self):
        res = gdb_test_python_method("which('gdb')")
        lines = res.splitlines()
        self.assertIn("/gdb", lines[-1])
        res = gdb_test_python_method("which('__IDontExist__')")
        self.assertIn("Missing file `__IDontExist__`", res)


    def test_func_gef_convenience(self):
        func = "gef_convenience('meh')"
        res = gdb_test_python_method(func, target=BIN_LS)
        self.assertNoException(res)

    def test_func_parse_address(self):
        func = "parse_address('main+0x4')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "parse_address('meh')"
        res = gdb_test_python_method(func)
        self.assertException(res)


    def test_func_download_file(self):
        gdbsrv = start_gdbserver(BIN_LS)
        func = f"download_file('{BIN_LS}')"
        res = gdb_test_python_method(func)
        stop_gdbserver(gdbsrv)
        self.assertNoException(res)
