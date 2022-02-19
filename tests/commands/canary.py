"""
`canary` command test module
"""


from tests.utils import gdb_start_silent_cmd, gdb_run_cmd, _target
from tests.utils import GefUnitTestGeneric


class CanaryCommand(GefUnitTestGeneric):
    """`canary` command test module"""


    def test_cmd_canary(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("canary"))
        res = gdb_start_silent_cmd("canary", target=_target("canary"))
        self.assertNoException(res)
        self.assertIn("The canary of process", res)
