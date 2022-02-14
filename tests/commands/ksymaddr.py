"""
`ksymaddr` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd


class KsymaddrCommand(GefUnitTestGeneric):
    """`ksymaddr` command test module"""


    cmd = "ksymaddr"


    def test_cmd_ksymaddr(self):
        res = gdb_run_cmd(f"{self.cmd} prepare_kernel_cred")
        self.assertNoException(res)
        self.assertIn("Found matching symbol for 'prepare_kernel_cred'", res)
