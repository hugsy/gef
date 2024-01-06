"""
`gef.arch` test module.
"""


import pytest

from tests.utils import ARCH, is_64b, debug_target, RemoteGefUnitTestGeneric


class GefArchApi(RemoteGefUnitTestGeneric):
    """`gef.arch` test module."""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_api_gef_arch_ptrsize(self):
        if is_64b():
            self.assertEqual(self._gef.arch.ptrsize, 8)
        else:
            self.assertEqual(self._gef.arch.ptrsize, 4)

    @pytest.mark.skipif(ARCH != "x86_64", reason=f"Skipped for {ARCH}")
    def test_api_gef_arch_x86_64(self):
        arch = self._gef.arch
        self.assertEqual(arch.arch, "X86")
        self.assertEqual(arch.mode, "64")

        self._gdb.execute("start")
        assert arch.flag_register_to_human(0).startswith("[zero carry parity adjust")
        assert arch.flag_register_to_human(None).lower().startswith("[zero carry parity adjust")


    @pytest.mark.skipif(ARCH != "i686", reason=f"Skipped for {ARCH}")
    def test_api_gef_arch_x86(self):
        arch = self._gef.arch
        self.assertEqual(arch.arch, "X86")
        self.assertEqual(arch.mode, "32")
