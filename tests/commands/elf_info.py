"""
elf-info command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class ElfInfoCommand(RemoteGefUnitTestGeneric):
    """`elf-info` command test module"""


    def test_cmd_elf_info(self):
        gdb = self._gdb
        res = gdb.execute("elf-info", to_string=True)
        self.assertIn("7f 45 4c 46", res)
