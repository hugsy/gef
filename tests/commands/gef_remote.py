"""
`gef_remote` command test module
"""

import random

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ARCH,
    GDBSERVER_DEFAULT_HOST,
    IN_GITHUB_ACTIONS,
    debug_target,
    gdbserver_session,
    qemuuser_session,
)


class GefRemoteCommand(RemoteGefUnitTestGeneric):
    """`gef_remote` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_cmd_gef_remote_gdbserver(self):
        gdb = self._gdb
        gef = self._gef
        root = self._conn.root
        gdbserver_mode = "GDBSERVER"
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        with gdbserver_session(port=port):
            gdb.execute(f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}")
            res: str = root.eval("str(gef.session.remote)")
            assert res.startswith(
                f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/"
            )
            assert res.endswith(f"pid={gef.session.pid}, mode={gdbserver_mode})")

    @pytest.mark.slow
    @pytest.mark.skipif(ARCH not in ("x86_64",), reason=f"Skipped for {ARCH}")
    def test_cmd_gef_remote_qemu_user(self):
        gdb = self._gdb
        gef = self._gef
        root = self._conn.root
        qemu_mode = "QEMU"
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        with qemuuser_session(port=port):
            cmd = f"gef-remote --qemu-user --qemu-binary {self._target} {GDBSERVER_DEFAULT_HOST} {port}"
            gdb.execute(cmd)
            res = root.eval("str(gef.session.remote)")
            assert res.startswith(
                f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/"
            )
            assert res.endswith(f"pid={gef.session.pid}, mode={qemu_mode})")

    def test_cmd_target_remote(self):
        gdb = self._gdb
        gef = self._gef
        root = self._conn.root
        gdbserver_mode = "GDBSERVER"
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        with gdbserver_session(port=port) as _:
            gdb.execute(f"target remote {GDBSERVER_DEFAULT_HOST}:{port}")
            res: str = root.eval("str(gef.session.remote)")
            assert res.startswith("RemoteSession(target=':0', local='/tmp/")
            assert res.endswith(f"pid={gef.session.pid}, mode={gdbserver_mode})")

    def assert_local_session_restored(self):
        """Check that GEF is back to a clean LOCAL state: no remote session, not initializing,
        and the default objfile handler is installed again (the remote one ignores local
        files, so a newly loaded file would not be registered as a module)."""
        gdb = self._gdb
        root = self._conn.root

        # evaluate first: pytest cannot introspect rpyc proxies in a failing assert
        remote = root.eval("repr(gef.session.remote)")
        initializing = bool(root.eval("gef.session.remote_initializing"))
        remote_debug = bool(root.eval("is_remote_debug()"))
        assert remote == "None"
        assert initializing is False
        assert remote_debug is False

        other = debug_target("bss")
        gdb.execute(f"file {other}")
        handled = bool(
            root.eval(
                f"any(str(m.path) == {str(other)!r} for m in gef.session.modules)"
            )
        )
        assert handled, "new objfile was not handled by `new_objfile_handler`"

    def test_cmd_gef_remote_connection_failure(self):
        """A failed `gef-remote` must not leave GEF stuck in the CONNECTING state, nor with
        the remote objfile handler installed."""
        gdb = self._gdb
        port = random.randint(1025, 65535)  # nothing listening

        with pytest.raises(Exception, match="Failed to setup remote target"):
            gdb.execute(f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}")

        self.assert_local_session_restored()

    def test_cmd_gef_remote_setup_exception(self):
        """An exception raised while setting up the remote session (after connecting) must
        still bring GEF back to a clean LOCAL state."""
        gdb = self._gdb
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        # Run as a user would (no debug): the error is reported instead of propagated. This
        # also avoids the debug traceback printer, which cannot show frames defined via `pi`.
        gdb.execute("gef config gef.debug False")
        gdb.execute("pi GefRemoteSessionManager.setup = lambda self: 1 / 0")
        with gdbserver_session(port=port):
            res = gdb.execute(
                f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}", to_string=True
            )
            assert "division by zero" in res

            self.assert_local_session_restored()

    @pytest.mark.skipif(
        ARCH == "aarch64" and IN_GITHUB_ACTIONS, reason=f"Skipped for {ARCH} on CI"
    )
    def test_cmd_gef_remote_session_ends_on_exit(self):
        """Once the remote process exits, the remote session is torn down and its temporary
        directory removed."""
        gdb = self._gdb
        root = self._conn.root
        while True:
            port = random.randint(1025, 65535)
            if port != self._port:
                break

        with gdbserver_session(port=port):
            gdb.execute(f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}")
            local_root = root.eval("str(gef.session.remote.root)")
            assert root.eval(f"pathlib.Path({local_root!r}).is_dir()")

            gdb.execute("continue")

            assert root.eval(f"not pathlib.Path({local_root!r}).exists()")
            self.assert_local_session_restored()
