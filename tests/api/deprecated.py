"""
test module for deprecated functions
"""

import pytest

from tests.utils import gdb_start_silent_cmd, gdb_test_python_method
from tests.utils import GefUnitTestGeneric


class GefFuncDeprecatedApi(GefUnitTestGeneric):
    """"""

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

        for cmd in old_stuff:
            with pytest.warns(Warning) as record:
                res = gdb_test_python_method(f"{cmd}")
                self.assertNoException(res)
                if not record:
                    pytest.fail("Expected a warning!")

