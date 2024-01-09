"""
`xfiles` command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class XfilesCommand(RemoteGefUnitTestGeneric):
    """`xfiles` command test module"""

    def test_cmd_xfiles(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("xfiles", to_string=True)
        )
        gdb.execute("start")
        res = gdb.execute("xfiles", to_string=True)
        self.assertGreaterEqual(len(res.splitlines()) , 3)
