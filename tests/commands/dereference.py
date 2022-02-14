"""
dereference command test module
"""


from tests.utils import gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class DereferenceCommand(GefUnitTestGeneric):
    """`dereference` command test module"""


    def test_cmd_dereference(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("dereference"))

        res = gdb_start_silent_cmd("dereference $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 2)

        res = gdb_start_silent_cmd("dereference 0x0")
        self.assertNoException(res)
        self.assertIn("Unmapped address", res)
