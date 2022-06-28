"""
Pattern commands test module
"""
import pytest

from tests.utils import ARCH, GefUnitTestGeneric, _target, gdb_run_cmd, is_64b


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


    @pytest.mark.skipif(ARCH not in ("x86_64", "aarch64", "i686", "armv7l"),
                        reason=f"Skipped for {ARCH}")
    def test_cmd_pattern_search(self):
        target = _target("pattern")
        if ARCH == "aarch64":
            lookup_register = "$x30"
            expected_offsets = (16, 16, 5, 9)
        elif ARCH == "armv7l":
            lookup_register = "$r11"
            expected_offsets = (8, 8, 5, 9)
        elif ARCH == "x86_64":
            lookup_register = "$rbp"
            expected_offsets = (8, 8, 5, 9)
        elif ARCH == "i686":
            lookup_register = "$ebp"
            # expected_offsets = (16, None, 5, 9)
            expected_offsets = (16, 16, 5, 9)
        else:
            raise ValueError("Invalid architecture")

        #0
        cmd = f"pattern search -n 4 {lookup_register}"
        before = ("set args aaaabaaacaaadaaaeaaafaaagaaahaaa", "run")
        res = gdb_run_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn(f"Found at offset {expected_offsets[0]} (little-endian search) likely", res)

        #1
        if is_64b():
            cmd = f"pattern search -n 8 {lookup_register}"
            before = ("set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", "run")
            res = gdb_run_cmd(cmd, before=before, target=target)
            self.assertNoException(res)
            self.assertIn(f"Found at offset {expected_offsets[1]} (little-endian search) likely", res)

        #2
        cmd = "pattern search -n 4 caaa"
        before = ("set args aaaabaaacaaadaaaeaaafaaagaaahaaa", "run")
        res = gdb_run_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn(f"Found at offset {expected_offsets[2]} (little-endian search) likely", res)

        #3
        if is_64b():
            cmd = "pattern search -n 8 caaaaaaa"
            before = ("set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", "run")
            res = gdb_run_cmd(cmd, before=before, target=target)
            self.assertNoException(res)
            self.assertIn(f"Found at offset {expected_offsets[3]} (little-endian search) likely", res)

        #4
        cmd = "pattern search -n 4 JUNK"
        before = ("set args aaaabaaacaaadaaaeaaafaaagaaahaaa", "run")
        res = gdb_run_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn(f"not found", res)

