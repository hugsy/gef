"""
Tests GEF internal functions.
"""

import pathlib
import tempfile
import subprocess
import os
import pytest

from tests.utils import (
    _target,
    gdb_start_silent_cmd,
    gdb_test_python_method,
    GefUnitTestGeneric,
)


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
        res = gdb_test_python_method(func, target=_target("default"))
        self.assertNoException(res)

    def test_func_parse_address(self):
        func = "parse_address('main+0x4')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "parse_address('meh')"
        res = gdb_test_python_method(func)
        self.assertException(res)

    def test_func_parse_maps(self):
        func = "Permission.from_info_sections(' [10]     0x555555574000->0x55555557401b at 0x00020000: .init ALLOC LOAD READONLY CODE HAS_CONTENTS')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "Permission.from_process_maps('0x0000555555554000 0x0000555555574000 0x0000000000000000 r-- /usr/bin/bash')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "Permission.from_info_mem('ffffff2a65e0b000-ffffff2a65e0c000 0000000000001000 -r-')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

    @pytest.mark.slow
    @pytest.mark.online
    @pytest.mark.skip
    def test_func_update_gef(self):
        bkp_home = os.environ["HOME"]
        for branch in ("main", "dev"):
            with tempfile.TemporaryDirectory() as tmpdir:
                dirpath = pathlib.Path(tmpdir)
                os.environ["HOME"] = str(dirpath.absolute())
                url = f"https://api.github.com/repos/hugsy/gef/git/ref/heads/{branch}"
                cmd = f"""wget -q -O- {url} | grep '"sha"' | tr -s ' ' | """ \
                       """cut -d ' ' -f 3 | tr -d ',' | tr -d '"' """
                ref = subprocess.check_output(cmd, shell=True).decode("utf-8").strip()
                res = gdb_test_python_method(f"update_gef(['--{branch}'])")
                retcode = int(res.splitlines()[-1])
                self.assertEqual(retcode, 0)
                home = pathlib.Path().home()
                self.assertEqual(open(f"{home}/.gdbinit", "r").read(), f"source ~/.gef-{ref}.py\n")
                fpath = home / f".gef-{ref}.py"
                self.assertTrue(fpath.exists())
        os.environ["HOME"] = bkp_home


    def test_func_show_last_exception(self):
        cmd = "hexdump byte *0"
        res = gdb_start_silent_cmd(cmd, before=("gef config gef.debug 1",))
        self.assertException(res)
