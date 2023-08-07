"""
`gef_remote` command test module
"""


from tests.utils import (GefUnitTestGeneric, _target, gdb_run_cmd,
                         gdbserver_session, qemuuser_session)

GDBSERVER_PREFERED_HOST = "localhost"
GDBSERVER_PREFERED_PORT = 1234

class GefRemoteCommand(GefUnitTestGeneric):
    """`gef_remote` command test module"""


    def test_cmd_gef_remote(self):
        port = GDBSERVER_PREFERED_PORT + 1
        before = [f"gef-remote {GDBSERVER_PREFERED_HOST} {port}"]
        with gdbserver_session(port=port) as _:
            res = gdb_run_cmd(
                "pi print(gef.session.remote)", before=before)
            self.assertNoException(res)
            self.assertIn(
                f"RemoteSession(target='{GDBSERVER_PREFERED_HOST}:{port}', local='/tmp/", res)
            self.assertIn(", qemu_user=False)", res)


    def test_cmd_gef_remote_qemu_user(self):
        port = GDBSERVER_PREFERED_PORT + 2
        target = _target("default")
        before = [
            f"gef-remote --qemu-user --qemu-binary {target} {GDBSERVER_PREFERED_HOST} {port}"]
        with qemuuser_session(port=port) as _:
            res = gdb_run_cmd(
                "pi print(gef.session.remote)", before=before)
            self.assertNoException(res)
            self.assertIn(
                f"RemoteSession(target='{GDBSERVER_PREFERED_HOST}:{port}', local='/tmp/", res)
            self.assertIn(", qemu_user=True)", res)
