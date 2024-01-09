"""
Test GEF configuration parameters.
"""

from typing import List

import pytest
from tests.base import RemoteGefUnitTestGeneric
from tests.utils import GEF_RIGHT_ARROW


class TestGefConfigUnit(RemoteGefUnitTestGeneric):
    """Test GEF configuration parameters."""

    def test_config_show_opcodes_size(self):
        """Check opcodes are correctly shown."""
        gdb = self._gdb

        max_opcode_len = 4
        #
        # Only show the code pane, limit the opcode size to 4 bytes (8 chars)
        #
        gdb.execute("gef config context.layout code")
        gdb.execute(f"gef config context.show_opcodes_size {max_opcode_len}")

        gdb.execute("start")
        lines: List[str] = gdb.execute("context", to_string=True).splitlines()[1:-1]
        self.assertGreater(len(lines), 1)

        #
        # For each line, check the format
        #
        # output format: 0xaddress   opcode[...]  <symbol+offset>   mnemo  [operands, ...]
        # example: 0x5555555546b2 897dec      <main+8>         mov    DWORD PTR [rbp-0x14], edi
        #
        for line in lines:
            parts = line.replace(GEF_RIGHT_ARROW, "").split()
            opcode: str = parts[1].replace("...", "").lower()
            assert (
                len(opcode) <= max_opcode_len * 2
            ), f"Invalid length for {opcode=}: {len(opcode)}"
            assert all(map(lambda c: c in "0123456789abcdef", opcode))

    def test_config_hook_validator(self):
        """Check that a GefSetting hook can prevent setting a config."""
        gdb = self._gdb

        res = gdb.execute(
            "gef config gef.tempdir '/tmp/path with space'", to_string=True
        )
        # Validators just use `err` to print an error
        self.assertRegex(res, r"[!].+Cannot set.+setting cannot contain spaces")

        gdb.execute("gef config gef.tempdir '/tmp/valid-path'")
        res = gdb.execute("gef config gef.tempdir", to_string=True).splitlines()[1]
        assert res == 'gef.tempdir (str) = "/tmp/valid-path"'

    def test_config_type_validator(self):
        """Check that a GefSetting type can prevent setting a config."""
        gdb = self._gdb

        res = gdb.execute("gef config gef.debug invalid", to_string=True)
        self.assertRegex(res, r"[!].+expects type 'bool'")

        gdb.execute("gef config gef.debug true")
        gdb.execute("gef config gef.debug 1")
        gdb.execute("gef config gef.debug F")
        gdb.execute("gef config gef.debug 0")

        output = gdb.execute("gef config gef.debug 'fooo'", to_string=True).strip()
        assert output == "[!] 'gef.debug' expects type 'bool', got str: reason cannot parse 'fooo' as bool"


    def test_config_libc_version(self):
        """Check setting libc version."""
        gdb = self._gdb

        #
        # When starting, should be empty
        #
        res = gdb.execute("gef config gef.libc_version", to_string=True).splitlines()[1]
        assert res == 'gef.libc_version (str) = ""'

        gdb.execute("gef config gef.libc_version 2.31")
        gdb.execute("start")

        res = gdb.execute("gef config gef.libc_version 2.31", to_string=True)
        res = gdb.execute("gef config gef.libc_version", to_string=True).splitlines()[1]
        assert res == 'gef.libc_version (str) = "2.31"'
