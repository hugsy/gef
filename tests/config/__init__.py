"""
Test GEF configuration parameters.
"""

from tests.utils import gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class TestGefConfigUnit(GefUnitTestGeneric):
    """Test GEF configuration parameters."""


    def test_config_show_opcodes_size(self):
        """Check opcodes are correctly shown."""
        res = gdb_run_cmd("entry-break", before=["gef config context.show_opcodes_size 4"])
        self.assertNoException(res)
        self.assertGreater(len(res.splitlines()), 1)

        # output format: 0xaddress   opcode  <symbol+offset>   mnemo  [operands, ...]
        # example: 0x5555555546b2 897dec      <main+8>         mov    DWORD PTR [rbp-0x14], edi
        self.assertRegex(res, r"(0x([0-9a-f]{2})+)\s+(([0-9a-f]{2})+)\s+<[^>]+>\s+(.*)")

    def test_config_hook_validator(self):
        """Check that a GefSetting hook can prevent setting a config."""
        res = gdb_run_cmd("gef config gef.tempdir '/tmp/path with space'")
        # Validators just use `err` to print an error
        self.assertNoException(res)
        self.assertRegex(res, r"[!].+Cannot set.+setting cannot contain spaces")

        res = gdb_run_cmd("gef config gef.tempdir '/tmp/valid-path'")
        self.assertNoException(res)
        self.assertNotIn("[!]", res)

    def test_config_type_validator(self):
        """Check that a GefSetting type can prevent setting a config."""
        res = gdb_run_cmd("gef config gef.debug invalid")
        self.assertNoException(res)
        self.assertRegex(res, r"[!].+expects type 'bool'")

        res = gdb_run_cmd("gef config gef.debug true")
        self.assertNoException(res)
        self.assertNotIn("[!]", res)
        res = gdb_run_cmd("gef config gef.debug 1")
        self.assertNoException(res)
        self.assertNotIn("[!]", res)
        res = gdb_run_cmd("gef config gef.debug F")
        self.assertNoException(res)
        self.assertNotIn("[!]", res)
        res = gdb_run_cmd("gef config gef.debug 0")
        self.assertNoException(res)
        self.assertNotIn("[!]", res)

    def test_config_libc_version(self):
        """Check setting libc version."""
        res = gdb_run_cmd("gef config gef.libc_version")
        self.assertNoException(res)
        self.assertNotIn("[!]", res)

        res = gdb_run_cmd("gef config gef.libc_version", before=["gef config gef.libc_version 2.31"])
        self.assertNoException(res)
        self.assertNotIn("[!]", res)
        self.assertIn('gef.libc_version (str) = "2.31"', res)

        res = gdb_run_cmd("gef config gef.libc_version", before=["gef config gef.libc_version 2.31", "gef config gef.libc_version ''"])
        self.assertNoException(res)
        self.assertNotIn("[!]", res)
        self.assertIn('gef.libc_version (str) = ""', res)

        res = gdb_start_silent_cmd("python print(gef.libc.version)", before=["gef config gef.libc_version 2.31"])
        self.assertNoException(res)
        self.assertNotIn("[!]", res)
