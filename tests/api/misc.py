"""
Tests GEF internal functions.
"""

import pathlib
import tempfile
import subprocess
import os
import pytest

from tests.utils import (
    debug_target,
    gdb_start_silent_cmd,
    gdb_test_python_method,
    gdb_run_cmd,
    gdbserver_session,
    qemuuser_session,
    GefUnitTestGeneric,
    GDBSERVER_DEFAULT_HOST,
    GDBSERVER_DEFAULT_PORT,
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
        res = gdb_test_python_method(func, target=debug_target("default"))
        self.assertNoException(res)

    def test_func_parse_address(self):
        func = "parse_address('main+0x4')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "parse_address('meh')"
        res = gdb_test_python_method(func)
        self.assertException(res)

    def test_func_parse_permissions(self):
        func = "Permission.from_info_sections('ALLOC LOAD READONLY CODE HAS_CONTENTS')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "Permission.from_process_maps('r--')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "Permission.from_monitor_info_mem('-r-')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

        func = "Permission.from_info_mem('rw')"
        res = gdb_test_python_method(func)
        self.assertNoException(res)

    def test_func_parse_maps(self):
        func = "list(GefMemoryManager.parse_procfs_maps())"
        res = gdb_test_python_method(func)
        self.assertNoException(res)
        assert "Section" in res

        func = "list(GefMemoryManager.parse_gdb_info_sections())"
        res = gdb_test_python_method(func)
        self.assertNoException(res)
        assert "Section" in res

        # When in a gef-remote session `parse_gdb_info_sections` should work to
        # query the memory maps
        port = GDBSERVER_DEFAULT_PORT + 1
        before = [f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}"]
        with gdbserver_session(port=port) as _:
            func = "list(GefMemoryManager.parse_gdb_info_sections())"
            res = gdb_test_python_method(func)
            self.assertNoException(res)
            assert "Section" in res

        # When in a gef-remote qemu-user session `parse_gdb_info_sections`
        # should work to query the memory maps
        port = GDBSERVER_DEFAULT_PORT + 2
        target = debug_target("default")
        before = [
            f"gef-remote --qemu-user --qemu-binary {target} {GDBSERVER_DEFAULT_HOST} {port}"]
        with qemuuser_session(port=port) as _:
            func = "list(GefMemoryManager.parse_gdb_info_sections())"
            res = gdb_test_python_method(func)
            self.assertNoException(res)
            assert "Section" in res

        # Running the _parse_maps method should just find the correct one
        func = "list(GefMemoryManager._parse_maps())"
        res = gdb_test_python_method(func)
        self.assertNoException(res)
        assert "Section" in res

        # The parse maps function should automatically get called when we start
        # up, and we should be able to view the maps via the `gef.memory.maps`
        # property.
        func = "gef.memory.maps"
        res = gdb_test_python_method(func)
        self.assertNoException(res)
        assert "Section" in res


    @pytest.mark.slow
    @pytest.mark.online
    @pytest.mark.skip
    def test_func_update_gef(self):
        bkp_home = os.environ["HOME"]
        for branch in ("main", ):
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
