"""
vmmap command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class VmmapCommand(RemoteGefUnitTestGeneric):
    """`vmmap` command test module"""

    def test_cmd_vmmap(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("vmmap", to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute("vmmap", to_string=True)
        self.assertGreater(len(res.splitlines()), 1)

        res = gdb.execute("vmmap stack", to_string=True)
        assert "`stack` has no type specified. We guessed it was a name filter." in res
        self.assertEqual(len(res.splitlines()), 9)

        res = gdb.execute("vmmap $pc", to_string=True)
        assert "`$pc` has no type specified. We guessed it was an address filter." in res
        self.assertEqual(len(res.splitlines()), 8)

    def test_cmd_vmmap_addr(self):
        gef, gdb = self._gef, self._gdb
        gdb.execute("start")

        pc = gef.arch.register("pc")

        res = gdb.execute(f"vmmap -a {pc:#x}", to_string=True)
        self.assertEqual(len(res.splitlines()), 5)

        res = gdb.execute("vmmap --addr $pc", to_string=True)
        self.assertEqual(len(res.splitlines()), 5)

    def test_cmd_vmmap_name(self):
        gdb = self._gdb
        gdb.execute("start")

        res = gdb.execute("vmmap -n stack", to_string=True)
        self.assertEqual(len(res.splitlines()), 5)

        res = gdb.execute("vmmap --name stack", to_string=True)
        self.assertEqual(len(res.splitlines()), 5)
