"""
Pattern commands test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH, debug_target, is_64b


class PatternCommand(RemoteGefUnitTestGeneric):
    """`pattern` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("pattern")
        return super().setUp()

    def test_cmd_pattern_create(self):
        gdb = self._gdb
        cmd = "pattern create -n 4 32"
        res = gdb.execute(cmd, to_string=True).strip()
        self.assertIn("aaaabaaacaaadaaaeaaaf", res)

        cmd = "pattern create -n 8 32"
        res = gdb.execute(cmd, to_string=True).strip()
        self.assertIn("aaaaaaaabaaaaaaacaaaaaaadaaaaaaa", res)

    @pytest.mark.skipif(
        ARCH not in ("x86_64", "aarch64", "i686", "armv7l"),
        reason=f"Skipped for {ARCH}",
    )
    def test_cmd_pattern_search(self):
        gdb = self._gdb
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

        # 0
        cmd = f"pattern search -n 4 {lookup_register}"
        gdb.execute("set args aaaabaaacaaadaaaeaaafaaagaaahaaa")
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn(
            f"Found at offset {expected_offsets[0]} (little-endian search) likely", res
        )

        # 1
        if is_64b():
            cmd = f"pattern search -n 8 {lookup_register}"
            gdb.execute("set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa")
            gdb.execute("run")
            res = gdb.execute(cmd, to_string=True)
            self.assertIn(
                f"Found at offset {expected_offsets[1]} (little-endian search) likely",
                res,
            )

        # 2
        cmd = "pattern search -n 4 caaa"
        gdb.execute("set args aaaabaaacaaadaaaeaaafaaagaaahaaa")
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn(
            f"Found at offset {expected_offsets[2]} (little-endian search) likely", res
        )

        # 3
        if is_64b():
            cmd = "pattern search -n 8 caaaaaaa"
            gdb.execute("set args aaaaaaaabaaaaaaacaaaaaaadaaaaaaa")
            gdb.execute("run")
            res = gdb.execute(cmd, to_string=True)
            self.assertIn(
                f"Found at offset {expected_offsets[3]} (little-endian search) likely",
                res,
            )

        # 4
        cmd = "pattern search -n 4 JUNK"
        gdb.execute("set args aaaabaaacaaadaaaeaaafaaagaaahaaa")
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("not found", res)

    @pytest.mark.skipif(not is_64b(), reason="Requires a 64-bit (8-byte) pattern")
    def test_cmd_pattern_offset_length_sync(self):
        gdb = self._gdb
        gdb.execute("start")
        gdb.execute("pattern create 1200")
        res = gdb.execute("pattern offset 0x6661616161616165", to_string=True)
        self.assertIn("Found at offset 1032 (little-endian search) likely", res)
