"""
`gef_remote` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdbserver_session

GDBSERVER_PREFERED_HOST = "localhost"
GDBSERVER_PREFERED_PORT = 1234

class GefRemoteCommand(GefUnitTestGeneric):
    """`gef_remote` command test module"""


    def test_cmd_gef_remote(self):
        before = [f"gef-remote {GDBSERVER_PREFERED_HOST} {GDBSERVER_PREFERED_PORT}"]
        with gdbserver_session(port=GDBSERVER_PREFERED_PORT) as _:
            res = gdb_run_cmd(
                "pi print(gef.session.remote)", before=before)
            self.assertNoException(res)
            self.assertIn(
                f"RemoteSession(target='{GDBSERVER_PREFERED_HOST}:{GDBSERVER_PREFERED_PORT}', local='/tmp/", res)


