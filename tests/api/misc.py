"""
Tests GEF internal functions.
"""

import pathlib
import pytest


from tests.base import RemoteGefUnitTestGeneric

from tests.utils import (
    debug_target,
)


class MiscFunctionTest(RemoteGefUnitTestGeneric):
    """Tests GEF internal functions."""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_func_which(self):
        root = self._conn.root

        res = root.eval("which('gdb')")
        assert isinstance(res, pathlib.Path)
        assert res.name == "gdb"

        with pytest.raises(FileNotFoundError):
            root.eval("which('__IDontExist__')")

    def test_func_gef_convenience(self):
        root = self._conn.root
        root.eval("gef_convenience('meh')")

    def test_func_parse_address(self):
        root = self._conn.root
        assert isinstance(root.eval("parse_address('main+0x4')"), int)

        with pytest.raises(Exception):
            root.eval("parse_address('meh')")

    def test_func_show_last_exception(self):
        gdb = self._gdb
        gdb.execute("start")

        #
        # Test debug info collection
        #
        gdb.execute("gef config gef.debug True")
        gdb.execute("gef config gef.propagate_debug_exception False")
        output: str = gdb.execute("hexdump byte *0", to_string=True)
        for title in (
            "Exception raised",
            "Version",
            "Last 10 GDB commands",
            "Runtime environment",
        ):
            assert title in output

        #
        # Test exception propagation
        #
        gdb.execute("gef config gef.propagate_debug_exception True")
        with pytest.raises(Exception):
            gdb.execute("hexdump byte *0")

    def test_func_process_lookup_path(self):
        root, gdb = self._conn.root, self._gdb
        gdb.execute("start")

        assert root.eval("process_lookup_path('meh')") is None

        libc = root.eval("process_lookup_path('libc')")
        assert libc is not None
        assert "libc" in pathlib.Path(libc.path).name

        assert root.eval("process_lookup_path('stack')") is not None

    def test_func_from_filter_repr(self):
        root = self._conn.root
        Permission = root.eval("Permission")

        none = Permission.from_filter_repr("---")
        assert len(none) == 1
        assert none[0] == Permission.NONE

        all_readable_perms = Permission.from_filter_repr("r??")
        assert all(x & Permission.READ for x in all_readable_perms)
        assert len(all_readable_perms) == 4

        all_writable_perms = Permission.from_filter_repr("?w?")
        assert all(x & Permission.WRITE for x in all_writable_perms)
        assert len(all_writable_perms) == 4

        all_executable_perms = Permission.from_filter_repr("??x")
        assert all(x & Permission.EXECUTE for x in all_executable_perms)
        assert len(all_executable_perms) == 4
