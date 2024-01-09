"""
test module for deprecated functions
"""


import pytest
from tests.base import RemoteGefUnitTestGeneric
from tests.utils import WARNING_DEPRECATION_MESSAGE


class GefFuncDeprecatedApi(RemoteGefUnitTestGeneric):
    """Test class for deprecated functions and variables. Each of those tests expect to receive a
    deprecation warning."""

    def test_deprecated_elf_values(self):
        gdb = self._gdb

        old_stuff = (
            "Elf.X86_64",
            "Elf.X86_32",
            "Elf.ARM",
            "Elf.MIPS",
            "Elf.POWERPC",
            "Elf.POWERPC64",
            "Elf.SPARC",
            "Elf.SPARC64",
            "Elf.AARCH64",
            "Elf.RISCV",
        )

        for item in old_stuff:
            output = gdb.execute(f"pi {item}", to_string=True)
            assert WARNING_DEPRECATION_MESSAGE in output

    def test_deprecated_gef_attributes(self):
        root = self._conn.root
        old_attributes = (
            "gef.gdb.loaded_commands",
            "gef.gdb.loaded_functions",
            "gef.gdb.missing_commands",
        )

        for i in old_attributes:
            with pytest.raises(Exception, match="ObsoleteException"):
                root.eval(i)
