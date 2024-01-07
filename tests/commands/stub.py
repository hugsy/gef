"""
stub command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class StubCommand(RemoteGefUnitTestGeneric):
    """`stub` command test module"""

    def test_cmd_stub(self):
        gdb = self._gdb
        # due to compiler optimizations printf might be converted to puts
        cmds = ("stub printf", "stub puts")
        for cmd in cmds:
            self.assertEqual(
                ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
            )

        gdb.execute("start")
        res = gdb.execute("continue", to_string=True).strip()
        self.assertIn("Hello World!", res)

        for cmd in cmds:
            gdb.execute("start")
            res = gdb.execute(cmd, to_string=True)
            self.assertNotIn("Hello World!", res)
            gdb.execute("continue")
