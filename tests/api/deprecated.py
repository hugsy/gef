"""
test module for deprecated functions
"""



from tests.utils import WARNING_DEPRECATION_MESSAGE, RemoteGefUnitTestGeneric


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
            self.assertIn(WARNING_DEPRECATION_MESSAGE, output)
