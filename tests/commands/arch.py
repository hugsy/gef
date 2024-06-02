"""
Arch commands test module
"""

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ARCH,
    ERROR_INACTIVE_SESSION_MESSAGE,
    debug_target,
    findlines,
    is_32b,
    is_64b,
)


class ArchCommand(RemoteGefUnitTestGeneric):
    """Generic class for command testing, that defines all helpers"""

    def setUp(self) -> None:
        return super().setUp()

    def test_cmd_arch_get(self):
        gdb = self._gdb

        res = gdb.execute("arch get", to_string=True)
        self.assertIn(" Architecture(X86, 64, LITTLE_ENDIAN)", res)
        self.assertIn(" The architecture has been detected via the ELF headers", res)

    def test_cmd_arch_set(self):
        gdb = self._gdb

        res = gdb.execute("arch get", to_string=True)
        self.assertIn(" Architecture(X86, 64, LITTLE_ENDIAN)", res)
        self.assertIn(" The architecture has been detected via the ELF headers", res)

        gdb.execute("arch set X86")

        res = gdb.execute("arch get", to_string=True)
        self.assertIn(" Architecture(Generic, None, LITTLE_ENDIAN)", res)
        self.assertIn(" The architecture has been set manually", res)

    def test_cmd_arch_list(self):
        gdb = self._gdb

        res = gdb.execute("arch list", to_string=True)
        self.assertIn("- GenericArchitecture", res)
        self.assertIn("- X86", res)
        self.assertIn("- X86_64", res)
