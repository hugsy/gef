from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    gdbserver_session,
)


class RegressionGdbserverConnection(RemoteGefUnitTestGeneric):
    def test_can_establish_connection_to_gdbserver_again_after_disconnect(self):
        """Ensure that gdb can connect to a gdbserver again after disconnecting (PR #896)."""
        gdb = self._gdb

        with gdbserver_session(port=5001) as _, gdbserver_session(port=5002) as _:
            gdb.execute("target remote :5001")
            gdb.execute("detach")

            gdb.execute("target remote :5002")
            gdb.execute("continue")
