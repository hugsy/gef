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
