"""
`gef.session` test module.
"""

import pathlib
import pytest

from tests.base import RemoteGefUnitTestGeneric

from tests.utils import (
    debug_target,
    gdbserver_session,
    qemuuser_session,
    GDBSERVER_DEFAULT_HOST,
)


class GefMemoryApi(RemoteGefUnitTestGeneric):
    """`gef.memory` test module."""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_api_gef_memory_only_running(self):
        gdb, gef = self._gdb, self._gef

        with pytest.raises(RuntimeError):
            assert gef.memory.maps is None

        gdb.execute("start")
        assert gef.memory.maps is not None


    def test_api_gef_memory_parse_info_proc_maps_expected_format(self):
        gdb, root = self._gdb, self._conn.root
        gdb.execute("start")

        #
        # The function assumes the following output format (as of GDB 8.3+) for `info proc mappings`
        # """"
        # process 61789
        # Mapped address spaces:
        #
        #           Start Addr           End Addr       Size     Offset  Perms  objfile
        #       0x555555554000     0x555555558000     0x4000        0x0  r--p   /usr/bin/ls
        #       0x555555558000     0x55555556c000    0x14000     0x4000  r-xp   /usr/bin/ls
        # [...]
        # """
        #

        # Check output format
        lines = (gdb.execute("info proc mappings", to_string=True) or "").splitlines()
        assert len(lines) >= 5
        assert all(map(lambda x: isinstance(x, str), lines))
        for line in lines[4:]:
            parts = [x.strip() for x in line.split()]
            start_addr = int(parts[0], 16)
            end_addr = int(parts[1], 16)
            size = int(parts[2], 16)
            int(parts[3], 16)
            assert end_addr == start_addr + size
            assert len(parts[4]) == 4
            Permission = root.eval("Permission")
            Permission.from_process_maps(parts[4])

            # optional objfile
            if len(parts) == 5:
                continue

            objfile = " ".join(parts[5:]).strip()
            if objfile.startswith("/"):
                assert pathlib.Path(objfile).exists()

    def test_api_gef_memory_parse_info_proc_maps(self):
        gdb, gef, root = self._gdb, self._gef, self._conn.root
        gdb.execute("start")

        Section = root.eval("Section")

        for section in gef.memory.parse_gdb_info_proc_maps():
            assert isinstance(section, Section)
