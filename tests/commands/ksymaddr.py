"""
`ksymaddr` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class KsymaddrCommand(RemoteGefUnitTestGeneric):
    """`ksymaddr` command test module"""

    cmd = "ksymaddr"

    def test_cmd_ksymaddr(self):
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd} prepare_kernel_cred", to_string=True)
        self.assertIn("Found matching symbol for 'prepare_kernel_cred'", res)
