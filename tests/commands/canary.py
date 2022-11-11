"""
`canary` command test module
"""


from tests.utils import gdb_start_silent_cmd, gdb_run_cmd, _target
from tests.utils import GefUnitTestGeneric
import platform

class CanaryCommand(GefUnitTestGeneric):
    """`canary` command test module"""


    def test_cmd_canary(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("canary"))
        res = gdb_start_silent_cmd("canary", target=_target("canary"))
        self.assertNoException(res)
        self.assertIn("The canary of process", res)
        # On other platforms, we read the canary from the auxiliary vector -
        # overwriting this value does not overwrite the in-use canary so it
        # is not tested
        if platform.machine() == "x86_64":
            patch = r"pi gef.memory.write(gef.arch.canary_address(), b'\xef\xbe\xad\xde')"
            res = gdb_start_silent_cmd(patch, target=_target("canary"), after=["canary"])
            self.assertNoException(res)
            self.assertIn("0xdeadbeef", res)
