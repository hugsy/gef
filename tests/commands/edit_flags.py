"""
`edit-flags` command test module
"""


import pytest

from tests.utils import ARCH, GefUnitTestGeneric, gdb_start_silent_cmd_last_line


class EditFlagsCommand(GefUnitTestGeneric):
    """`edit-flags` command test module"""


    @pytest.mark.skipif(ARCH not in ["i686", "x86_64", "armv7l", "aarch64"],
                        reason=f"Skipped for {ARCH}")
    def test_cmd_edit_flags(self):
        # force enable flag
        res = gdb_start_silent_cmd_last_line("edit-flags +carry")
        self.assertNoException(res)
        self.assertIn("CARRY ", res)
        # force disable flag
        res = gdb_start_silent_cmd_last_line("edit-flags -carry")
        self.assertNoException(res)
        self.assertIn("carry ", res)
        # toggle flag
        res = gdb_start_silent_cmd_last_line("edit-flags")
        flag_set = "CARRY " in res
        res = gdb_start_silent_cmd_last_line("edit-flags ~carry")
        self.assertNoException(res)
        if flag_set:
            self.assertIn("carry ", res)
        else:
            self.assertIn("CARRY ", res)
