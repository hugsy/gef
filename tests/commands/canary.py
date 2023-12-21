"""
`canary` command test module
"""


from tests.utils import gdb_start_silent_cmd, gdb_run_cmd, debug_target, gdb_test_python_method
from tests.utils import GefUnitTestGeneric
import pytest
import platform

ARCH = platform.machine()

class CanaryCommand(GefUnitTestGeneric):
    """`canary` command test module"""


    def test_cmd_canary(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("canary"))
        res = gdb_start_silent_cmd("canary", target=debug_target("canary"))
        self.assertNoException(res)
        self.assertIn("The canary of process", res)
        res = gdb_test_python_method("gef.session.canary[0] == gef.session.original_canary[0]")
        self.assertNoException(res)
        self.assertIn("True", res)

    @pytest.mark.skipif(ARCH != "x86_64", reason=f"Not implemented for {ARCH}")
    def test_overwrite_canary(self):
        patch = r"pi gef.memory.write(gef.arch.canary_address(), p64(0xdeadbeef))"
        res = gdb_start_silent_cmd(patch, target=debug_target("canary"), after=["canary"])
        self.assertNoException(res)
        self.assertIn("0xdeadbeef", res)
