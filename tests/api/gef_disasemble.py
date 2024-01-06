"""
`gef.heap` test module.
"""

import pytest

from tests.utils import ARCH, debug_target, RemoteGefUnitTestGeneric


class GefDisassembleApiFunction(RemoteGefUnitTestGeneric):
    """`gef_disassemble` function test module."""

    def setUp(self) -> None:
        self._target = debug_target("mmap-known-address")
        return super().setUp()

    @pytest.mark.skipif(ARCH not in ("x86_64", "i686"), reason=f"Skipped for {ARCH}")
    def test_func_gef_disassemble(self):
        self._gdb.execute("run")
        output = self._conn.root.eval("list(map(str,gef_disassemble(0x2337100, 4, 4)))")
        expected = [
            " 0x23370fc                  int3   ",
            " 0x23370fd                  int3   ",
            " 0x23370fe                  int3   ",
            " 0x23370ff                  int3   ",
            " 0x2337100                  int3   ",
            " 0x2337101                  int3   ",
            " 0x2337102                  int3   ",
            " 0x2337103                  int3   ",
        ]
        assert len(output) == len(expected)
        for i in range(len(output)):
            assert output[i] == expected[i]

    @pytest.mark.skipif(ARCH not in ("x86_64", "i686"), reason=f"Skipped for {ARCH}")
    def test_func_gef_disassemble_page_border(self):
        # Regression test for issue #922
        self._gdb.execute("run")
        output = self._conn.root.eval(
            "list(map(str,  gef_disassemble(0x2337000, 4, 4)))"
        )
        expected = [
            " 0x2337000                  int3   ",
            " 0x2337001                  int3   ",
            " 0x2337002                  int3   ",
            " 0x2337003                  int3   ",
        ]
        assert len(output) == len(expected)
        for i in range(len(output)):
            assert output[i] == expected[i]
