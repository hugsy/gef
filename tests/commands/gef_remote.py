"""
`gef_remote` command test module
"""

import random

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ARCH,
    debug_target,
    gdbserver_session,
    get_random_port,
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
        port = get_random_port()
        gdbserver_mode = "GDBSERVER"

        with gdbserver_session(port=port):
            gdb.execute(f"target remote {GDBSERVER_DEFAULT_HOST}:{port}")
            res: str = str(gef.session.remote)
            assert res.startswith(f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/")
            assert res.endswith(f"mode={gdbserver_mode}, pid={gef.session.pid})")

    @pytest.mark.slow
    @pytest.mark.skipif(ARCH not in ("x86_64",), reason=f"Skipped for {ARCH}")
    def test_cmd_gef_remote_qemu_user(self):
        gdb = self._gdb
        gef = self._gef
        qemu_mode = "QEMU_USER"
        port = get_random_port()

        with qemuuser_session(port=port):
            cmd = f"target remote {GDBSERVER_DEFAULT_HOST}:{port}"
            gdb.execute(cmd)
            res = str(gef.session.remote)
            assert res.startswith(f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/")
            assert res.endswith(f"mode={qemu_mode})")

    def test_cmd_target_remote(self):
        gdb = self._gdb
        gef = self._gef
        gdbserver_mode = "GDBSERVER"
        port = get_random_port()

        with gdbserver_session(port=port) as _:
            gdb.execute(f"target remote {GDBSERVER_DEFAULT_HOST}:{port}")
            res: str = str(gef.session.remote)
            assert res.startswith(
                f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/"
            )
            assert res.endswith(f"mode={gdbserver_mode}, pid={gef.session.pid})")
