"""
Tests GEF internal functions.
"""

import pathlib
import pytest
import random

from tests.base import RemoteGefUnitTestGeneric

from tests.utils import (
    debug_target,
    gdbserver_session,
    qemuuser_session,
    GDBSERVER_DEFAULT_HOST,
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

    def test_func_parse_permissions(self):
        root = self._conn.root
        expected_values = [
            (
                "Permission.from_info_sections('ALLOC LOAD READONLY CODE HAS_CONTENTS')",
                "r-x",
            ),
            ("Permission.from_process_maps('r--')", "r--"),
            ("Permission.from_monitor_info_mem('-r-')", "r--"),
            ("Permission.from_info_mem('rw')", "rw-"),
        ]
        for cmd, expected in expected_values:
            assert str(root.eval(cmd)) == expected

    def test_func_parse_maps_local_procfs(self):
        root, gdb, gef = self._conn.root, self._gdb, self._gef

        with pytest.raises(FileNotFoundError):
            root.eval("list(GefMemoryManager.parse_procfs_maps())")

        gdb.execute("start")

        sections = root.eval("list(GefMemoryManager.parse_procfs_maps())")
        for section in sections:
            assert section.page_start & ~0xFFF
            assert section.page_end & ~0xFFF

        # The parse maps function should automatically get called when we start
        # up, and we should be able to view the maps via the `gef.memory.maps`
        # property. So check the alias
        assert gef.memory.maps == sections

    def test_func_parse_maps_local_info_section(self):
        root, gdb = self._conn.root, self._gdb
        gdb.execute("start")

        sections = root.eval("list(GefMemoryManager.parse_gdb_info_sections())")
        assert len(sections) > 0

    @pytest.mark.slow
    def test_func_parse_maps_remote_gdbserver(self):
        root, gdb = self._conn.root, self._gdb
        # When in a gef-remote session `parse_gdb_info_sections` should work to
        # query the memory maps
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        with pytest.raises(Exception):
            gdb.execute(f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}")

        with gdbserver_session(port=port) as _:
            gdb.execute(f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}")
            sections = root.eval("list(GefMemoryManager.parse_gdb_info_sections())")
            assert len(sections) > 0

    def test_func_parse_maps_remote_qemu(self):
        root, gdb = self._conn.root, self._gdb
        # When in a gef-remote qemu-user session `parse_gdb_info_sections`
        # should work to query the memory maps
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        with qemuuser_session(port=port) as _:
            cmd = f"gef-remote --qemu-user --qemu-binary {self._target} {GDBSERVER_DEFAULT_HOST} {port}"
            gdb.execute(cmd)
            sections = root.eval("list(GefMemoryManager.parse_gdb_info_sections())")
            assert len(sections) > 0

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
