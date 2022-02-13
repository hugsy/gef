"""
test module for deprecated functions
"""

import pytest

from tests.utils import (
    gdb_test_python_method,
    GefUnitTestGeneric,
)

class GefFuncDeprecatedApi(GefUnitTestGeneric):
    """Test class for deprecated functions and variables. Each of those tests expect to receive a
    deprecation warning."""

    def test_deprecated_elf_values(self):
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
            with pytest.warns(Warning) as record:
                res = gdb_test_python_method(item)
                self.assertNoException(res)
                if not record:
                    pytest.fail(f"Expected a warning for '{item}'!")

