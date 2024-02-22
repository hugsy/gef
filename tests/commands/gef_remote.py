"""
`gef_remote` command test module
"""

import random

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    debug_target,
    gdbserver_session,
    qemuuser_session,
    GDBSERVER_DEFAULT_HOST,
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
            assert res.startswith(f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/")
            assert res.endswith(f"pid={gef.session.pid}, mode={gdbserver_mode})")

    @pytest.mark.slow
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
            assert res.startswith(f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/")
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
            assert res.startswith(f"RemoteSession(target=':0', local='/tmp/")
            assert res.endswith(f"pid={gef.session.pid}, mode={gdbserver_mode})")
