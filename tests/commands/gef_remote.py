"""
`gef_remote` command test module
"""


from tests.utils import gdb_start_silent_cmd, start_gdbserver, stop_gdbserver
from tests.utils import GefUnitTestGeneric


class GefRemoteCommand(GefUnitTestGeneric):
    """`gef_remote` command test module"""


    def test_cmd_gef_remote(self):
        before = ["gef-remote :1234"]
        gdbserver = start_gdbserver()
        res = gdb_start_silent_cmd("vmmap", before=before)
        self.assertNoException(res)
        stop_gdbserver(gdbserver)

