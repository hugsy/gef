"""
`gef_remote` command test module
"""


from tests.utils import (
    GefUnitTestGeneric,
    debug_target,
    gdb_run_cmd,
    gdbserver_session,
    qemuuser_session,
    GDBSERVER_DEFAULT_HOST,
    GDBSERVER_DEFAULT_PORT,
)

class GefRemoteCommand(GefUnitTestGeneric):
    """`gef_remote` command test module"""


    def test_cmd_gef_remote(self):
        port = GDBSERVER_DEFAULT_PORT + 1
        before = [f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}"]
        with gdbserver_session(port=port) as _:
            res = gdb_run_cmd(
                "pi print(gef.session.remote)", before=before)
            self.assertNoException(res)
            self.assertIn(
                f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/", res)
            self.assertIn(", qemu_user=False)", res)


    def test_cmd_gef_remote_qemu_user(self):
        port = GDBSERVER_DEFAULT_PORT + 2
        target = debug_target("default")
        before = [
            f"gef-remote --qemu-user --qemu-binary {target} {GDBSERVER_DEFAULT_HOST} {port}"]
        with qemuuser_session(port=port) as _:
            res = gdb_run_cmd(
                "pi print(gef.session.remote)", before=before)
            self.assertNoException(res)
            self.assertIn(
                f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/", res)
            self.assertIn(", qemu_user=True)", res)


    def test_cmd_target_remote(self):
        port = GDBSERVER_DEFAULT_PORT + 3
        before = [f"target remote {GDBSERVER_DEFAULT_HOST}:{port}"]
        with gdbserver_session(port=port) as _:
            res = gdb_run_cmd(
                "pi print(gef.session.remote)", before=before)
            self.assertNoException(res)
            self.assertIn(
                f"RemoteSession(target=':0', local='/tmp/", res)
            self.assertIn(", qemu_user=False)", res)
