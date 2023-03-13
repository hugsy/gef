"""
`gef.heap` test module.
"""

import pytest

from tests.utils import ARCH, _target, gdb_run_silent_cmd
from tests.utils import GefUnitTestGeneric


class GefDisassembleApiFunction(GefUnitTestGeneric):
    """`gef_disassemble` function test module."""

    @pytest.mark.skipif(ARCH not in ("x86_64", "i686"), reason=f"Skipped for {ARCH}")
    def test_func_gef_disassemble(self):
        cmd = "gef_disassemble(0x2337100, 4, 4)"
        res = gdb_run_silent_cmd(f"pi os.linesep.join([str(i) for i in {cmd}])", target=_target("mmap-known-address"))
        self.assertNoException(res)
        self.assertIn(
            ' 0x23370fc                  int3   \\n 0x23370fd                  int3   \\n 0x23370fe                  int3   \\n 0x23370ff                  int3   \\n 0x2337100                  int3   \\n 0x2337101                  int3   \\n 0x2337102                  int3   \\n 0x2337103                  int3   ', res)

    @pytest.mark.skipif(ARCH not in ("x86_64", "i686"), reason=f"Skipped for {ARCH}")
    def test_func_gef_disassemble_page_border(self):
        # Regression test for issue #922
        cmd = "gef_disassemble(0x2337000, 4, 4)"
        res = gdb_run_silent_cmd(
            f"pi os.linesep.join([str(i) for i in {cmd}])", target=_target("mmap-known-address"))
        self.assertNoException(res)
        self.assertIn(
            '0x2337000                  int3   \\n 0x2337001                  int3   \\n 0x2337002                  int3   \\n 0x2337003                  int3   ', res)
