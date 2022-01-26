"""
Pattern commands test module
"""
import pytest

from tests.utils import (
    gdb_run_cmd,
    gdb_start_silent_cmd,
    _target,

    ARCH,
    GefUnitTestGeneric
)


class PatternCommand(GefUnitTestGeneric):
    """`pattern` command test module"""

    def test_cmd_pattern_create(self):
        cmd = "pattern create -n 4 32"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("aaaabaaacaaadaaaeaaaf", res)

        cmd = "pattern create -n 8 32"
        res = gdb_run_cmd(cmd)
        self.assertNoException(res)
        self.assertIn("aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", res)


    @pytest.mark.skipif(ARCH not in ("x86_64", "aarch64"), reason=f"Skipped for {ARCH}")
    def test_cmd_pattern_search(self):
        target = _target("pattern")
        if ARCH == "aarch64":
            r = "$x30"
        elif ARCH == "x86_64":
            r = "$rbp"
        else:
            raise ValueError("Invalid architecture")

        cmd = f"pattern search -n 4 {r}"
        before = ["set args aaaabaaacaaadaaaeaaafaaagaaahaaa", "run"]
        res = gdb_run_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn("Found at offset", res)

        cmd = f"pattern search -n 8 {r}"
        before = ["set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", "run"]
        res = gdb_run_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn("Found at offset", res)

        res = gdb_start_silent_cmd("pattern search -n 4 caaaaaaa")
        self.assertNoException(res)
        self.assertNotIn("Found at offset", res)

        res = gdb_start_silent_cmd("pattern search -n 8 caaaaaaa")
        self.assertNoException(res)
        self.assertIn("Found at offset", res)

        res = gdb_start_silent_cmd("pattern search -n 8 0x6261616161616161")
        self.assertNoException(res)
        self.assertIn("Found at offset", res)
