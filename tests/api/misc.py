"""
Tests GEF internal functions.
"""

import pathlib
import tempfile
import subprocess
import os
import pytest

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


    @pytest.mark.slow
    @pytest.mark.online
    @pytest.mark.skip
    def test_func_update_gef(self):
        bkp_home = os.environ["HOME"]
        for branch in ("master", "dev"):
            with tempfile.TemporaryDirectory() as tmpdir:
                dirpath = pathlib.Path(tmpdir)
                os.environ["HOME"] = str(dirpath.absolute())
                ref = subprocess.check_output(f"""wget -q -O- https://api.github.com/repos/hugsy/gef/git/ref/heads/{branch} | grep '"sha"' | tr -s ' ' | cut -d ' ' -f 3 | tr -d ',' | tr -d '"' """, shell=True).decode("utf-8").strip()
                res = gdb_test_python_method(f"update_gef(['--{branch}'])")
                retcode = int(res.splitlines()[-1])
                self.assertEqual(retcode, 0)
                home = pathlib.Path().home()
                self.assertEqual(open(f"{home}/.gdbinit", "r").read(), f"source ~/.gef-{ref}.py\n")
                fpath = home / f".gef-{ref}.py"
                self.assertTrue(fpath.exists())
        os.environ["HOME"] = bkp_home
