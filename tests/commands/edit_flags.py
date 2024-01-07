"""
`edit-flags` command test module
"""


import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH


@pytest.mark.skipif(ARCH in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
class EditFlagsCommand(RemoteGefUnitTestGeneric):
    """`edit-flags` command test module"""

    def test_cmd_edit_flags_disable(self):
        gdb = self._gdb
        gef = self._gef

        with pytest.raises(gdb.error):
            gdb.execute("edit-flags")

        gdb.execute("start")
        res: str = gdb.execute("edit-flags", to_string=True).strip()
        assert res.startswith("[") and res.endswith("]")

        # pick first flag
        idx, name = next(gef.arch.flags_table)
        gdb.execute(f"edit-flags -{name}")
        assert gef.arch.register(gef.arch.flag_register) & (1 << idx) == 0

    def test_cmd_edit_flags_enable(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("start")

        idx, name = next(gef.arch.flags_table)
        gdb.execute(f"edit-flags +{name}")
        assert gef.arch.register(gef.arch.flag_register) & (1 << idx) != 0

    def test_cmd_edit_flags_toggle(self):
        gdb = self._gdb
        gef = self._gef

        idx, name = next(gef.arch.flags_table)
        init_val = gef.arch.register(gef.arch.flag_register) & (1 << idx)
        gdb.execute(f"edit-flags ~{name}")
        new_val = gef.arch.register(gef.arch.flag_register) & (1 << idx)
        assert init_val != new_val
