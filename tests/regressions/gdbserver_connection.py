from tests.utils import (
    GefUnitTestGeneric,
    gdb_run_cmd,
    gdbserver_session,
)


class RegressionGdbserverConnection(GefUnitTestGeneric):
    def test_can_establish_connection_to_gdbserver_again_after_disconnect(self):
        """Ensure that gdb can connect to a gdbserver again after disconnecting (PR #896)."""

        with gdbserver_session(port=5001) as _, gdbserver_session(port=5002) as _:
            buf = gdb_run_cmd("gef-remote 127.0.0.1 5001",
                              after=["detach", "gef-remote 127.0.0.1 5002", "continue"])
            self.assertNoException(buf)
