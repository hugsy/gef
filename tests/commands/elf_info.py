"""
elf-info command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class ElfInfoCommand(GefUnitTestGeneric):
    """`elf-info` command test module"""


    def test_cmd_elf_info(self):
        res = gdb_run_cmd("elf-info")
        self.assertNoException(res)
        self.assertIn("7f 45 4c 46", res)
