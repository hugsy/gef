"""
Test GEF configuration parameters.
"""


from tests.utils import gdb_run_cmd
from tests.utils import GefUnitTestGeneric


class TestGefConfigUnit(GefUnitTestGeneric):
    """Test GEF configuration paramaters."""


    def test_config_show_opcodes_size(self):
        """Check opcodes are correctly shown"""
        res = gdb_run_cmd("entry-break", before=["gef config context.show_opcodes_size 4"])
        self.assertNoException(res)
        self.assertGreater(len(res.splitlines()), 1)

        # output format: 0xaddress   opcode  <symbol+offset>   mnemo  [operands, ...]
        # example: 0x5555555546b2 897dec      <main+8>         mov    DWORD PTR [rbp-0x14], edi
        self.assertRegex(res, r"(0x([0-9a-f]{2})+)\s+(([0-9a-f]{2})+)\s+<[^>]+>\s+(.*)")

