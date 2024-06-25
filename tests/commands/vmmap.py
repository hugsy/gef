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
        self.assertGreater(len(res.splitlines()), 1)

        res = gdb.execute("vmmap $pc", to_string=True)
        self.assertEqual(len(res.splitlines()), 8)
