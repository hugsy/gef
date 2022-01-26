"""
`process-search` command test module
"""


from tests.utils import _target, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class ProcessSearchCommand(GefUnitTestGeneric):
    """`process-search` command test module"""


    def test_cmd_process_search(self):
        target = _target("pattern")
        res = gdb_start_silent_cmd("process-search", target=target,
                                   before=["set args w00tw00t"])
        self.assertNoException(res)
        self.assertIn(str(target), res)

        res = gdb_start_silent_cmd("process-search gdb.*fakefake",
                                   target=target, before=["set args w00tw00t"])
        self.assertNoException(res)
        self.assertIn("gdb", res)

        res = gdb_start_silent_cmd("process-search --smart-scan gdb.*fakefake",
                                   target=target, before=["set args w00tw00t"])
        self.assertNoException(res)
        self.assertNotIn("gdb", res)
