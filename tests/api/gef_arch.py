"""
`gef.arch` test module.
"""


import pytest

from tests.utils import ARCH, gdb_test_python_method
from tests.utils import GefUnitTestGeneric


class GefArchApi(GefUnitTestGeneric):
    """`gef.arch` test module."""

    def test_func_gef_arch_ptrsize(self):
        res = gdb_test_python_method("gef.arch.ptrsize")
        self.assertIn(res.splitlines()[-1], ("4", "8"))


    @pytest.mark.skipif(ARCH not in ["x86_64", "i686"], reason=f"Skipped for {ARCH}")
    def test_func_reset_architecture(self):
        res = gdb_test_python_method("gef.arch.arch, gef.arch.mode", before="reset_architecture()")
        res = (res.splitlines()[-1])
        self.assertIn("X86", res)
