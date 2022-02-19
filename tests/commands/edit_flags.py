"""
`edit-flags` command test module
"""


import pytest

from tests.utils import (
    ARCH,
    GefUnitTestGeneric,
    gdb_start_silent_cmd_last_line,
    gdb_start_silent_cmd,
)


@pytest.mark.skipif(ARCH not in ["i686", "x86_64", "armv7l", "aarch64"],
                    reason=f"Skipped for {ARCH}")
class EditFlagsCommand(GefUnitTestGeneric):
    """`edit-flags` command test module"""

    def setUp(self) -> None:
        res = gdb_start_silent_cmd_last_line("edit-flags")
        self.assertNoException(res)
        flags = res[1:-1].split()
        self.flag_name = "carry"
        self.initial_value = [f for f in flags if f.lower() == self.flag_name][0]
        return super().setUp()


    def test_cmd_edit_flags_disable(self):
        res = gdb_start_silent_cmd_last_line("edit-flags",
                                             after=(f"edit-flags +{self.flag_name}",
                                                    f"edit-flags -{self.flag_name}"))
        self.assertNoException(res)
        self.assertIn(self.flag_name.lower(), res)


    def test_cmd_edit_flags_enable(self):
        res = gdb_start_silent_cmd("edit-flags",
                                             after=(f"edit-flags -{self.flag_name}",
                                                    f"edit-flags +{self.flag_name}"))
        self.assertNoException(res)
        self.assertIn(self.flag_name.upper(), res)


    def test_cmd_edit_flags_toggle(self):
        res = gdb_start_silent_cmd_last_line(f"edit-flags ~{self.flag_name}")
        self.assertNoException(res)
        if self.initial_value == self.flag_name.upper():
            self.assertIn(self.flag_name.lower(), res)
        else:
            self.assertIn(self.flag_name.upper(), res)
