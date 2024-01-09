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

    def test_cmd_gef_remote(self):
        gdb = self._gdb
        root = self._conn.root
        while True:
            port = random.randint(1025, 65535)
            if port != self._port: break

        with gdbserver_session(port=port):
            gdb.execute(f"gef-remote {GDBSERVER_DEFAULT_HOST} {port}")
            res = root.eval("str(gef.session.remote)")
            self.assertIn(
                f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/", res)
            self.assertIn(", qemu_user=False)", res)


    @pytest.mark.slow
    def test_cmd_gef_remote_qemu_user(self):
        gdb = self._gdb
        root = self._conn.root
        while True:
            port = random.randint(1025, 65535)
            if port != self._port: break


        with qemuuser_session(port=port):
            cmd =             f"gef-remote --qemu-user --qemu-binary {self._target} {GDBSERVER_DEFAULT_HOST} {port}"
            gdb.execute(cmd)
            res = root.eval("str(gef.session.remote)")
            assert f"RemoteSession(target='{GDBSERVER_DEFAULT_HOST}:{port}', local='/tmp/" in res
            assert ", qemu_user=True)" in res


    def test_cmd_target_remote(self):
        gdb = self._gdb
        root = self._conn.root
        while True:
            port = random.randint(1025, 65535)
            if port != self._port: break

        with gdbserver_session(port=port) as _:
            gdb.execute(f"target remote {GDBSERVER_DEFAULT_HOST}:{port}")
            res = root.eval("str(gef.session.remote)")
            self.assertIn(f"RemoteSession(target=':0', local='/tmp/", res)
            self.assertIn(", qemu_user=False)", res)
