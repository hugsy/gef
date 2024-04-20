import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import debug_target


class RegressionFilenameCollisionLookup(RemoteGefUnitTestGeneric):
    """Tests for regression about collisions in filenames while using
    `process_lookup_path`
    """

    def setUp(self) -> None:
        self._target = debug_target("collision-libc/collision")
        return super().setUp()

    def test_process_lookup_path_use_only_filename(self):
        root, gdb = self._conn.root, self._gdb

        gdb.execute("start")
        program = root.eval("process_lookup_path('collision')")
        libc = root.eval("process_lookup_path('libc')")

        print(program)
        print(libc)

        assert program is not None
        assert libc is not None
        # TODO: Check if we can compare sections directly
        assert program.page_start != libc.page_start
