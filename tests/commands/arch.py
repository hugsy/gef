"""
Arch commands test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ARCH


class ArchCommand(RemoteGefUnitTestGeneric):
    """Class for `arch` command testing."""

    @pytest.mark.skipif(ARCH != "x86_64", reason=f"Skipped for {ARCH}")
    def test_cmd_arch_get(self):
        gdb = self._gdb

        res = gdb.execute("arch get", to_string=True)
        assert " Architecture(X86, 64, LITTLE_ENDIAN)" in res
        assert " The architecture has been detected via the ELF headers" in res

    def test_cmd_arch_set(self):
        gdb = self._gdb

        gdb.execute("arch set X86")

        res = gdb.execute("arch get", to_string=True)
        assert " Architecture(X86, 32, LITTLE_ENDIAN)" in res
        assert " The architecture has been set manually" in res


        gdb.execute("arch set ppc")

        res = gdb.execute("arch get", to_string=True)
        assert " Architecture(PPC, PPC32, LITTLE_ENDIAN)" in res
        assert " The architecture has been set manually" in res

    def test_cmd_arch_list(self):
        gdb = self._gdb

        res = gdb.execute("arch list", to_string=True)
        assert "- GenericArchitecture" not in res
        assert " Architecture(X86, 64, LITTLE_ENDIAN)" in res
        assert "  X86" in res
        assert "  X86_64" in res
