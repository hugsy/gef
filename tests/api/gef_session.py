"""
`gef.session` test module.
"""

import os
import pathlib
import random
import re

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ARCH,
    GDBSERVER_DEFAULT_HOST,
    debug_target,
    gdbserver_session,
    qemuuser_session,
)


class GefSessionApi(RemoteGefUnitTestGeneric):
    """`gef.session` test module."""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_func_remote_lifecycle_transitions(self):
        """`begin_remote()` / `attach_remote()` / `end_remote()` move the session between the
        LOCAL, CONNECTING and REMOTE states (PR #1243)."""
        root = self._conn.root

        # LOCAL -> CONNECTING -> LOCAL (failed connection, no session object yet)
        root.eval("gef.session.begin_remote()")
        assert root.eval("gef.session.remote_initializing")
        assert root.eval("is_remote_debug()")
        root.eval("gef.session.end_remote()")
        assert not root.eval("gef.session.remote_initializing")
        assert not root.eval("is_remote_debug()")

        # LOCAL -> CONNECTING -> REMOTE. The session is never connected, so closing it must
        # not touch the objfile handlers, only remove its temporary directory.
        session = root.eval("GefRemoteSessionManager('', 0)")
        local_root = str(session.root)
        root.eval("gef.session.begin_remote()")
        root.eval("gef.session.attach_remote")(session)
        assert bool(root.eval("gef.session.remote") == session)
        assert not root.eval("gef.session.remote_initializing")
        assert root.eval("is_remote_debug()")

        # only one remote session at a time
        with pytest.raises(Exception, match="already active"):
            root.eval("gef.session.begin_remote()")

        # REMOTE -> LOCAL, idempotent
        root.eval("gef.session.end_remote()")
        root.eval("gef.session.end_remote()")
        assert root.eval("gef.session.remote is None")
        assert not root.eval("is_remote_debug()")
        assert not root.eval(f"pathlib.Path({local_root!r}).exists()")

    def test_func_get_filepath(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("start")
        assert isinstance(gef.session.file, pathlib.Path)
        assert str(gef.session.file.absolute()) == str(self._target.absolute())

    def test_func_get_pid(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("start")

        pid_from_gdb = int(
            gdb.execute("info proc", to_string=True).splitlines()[0].split()[1]
        )
        assert gef.session.pid == pid_from_gdb

    def test_func_auxiliary_vector(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("start")

        assert "AT_PLATFORM" in gef.session.auxiliary_vector
        assert "AT_EXECFN" in gef.session.auxiliary_vector
        assert "AT_WHATEVER" not in gef.session.auxiliary_vector
        assert gef.session.auxiliary_vector["AT_PAGESZ"] == 0x1000

    def test_root_dir_local(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("start")

        assert gef.session.root
        result = self._conn.root.eval("os.stat(gef.session.root)")
        expected = os.stat("/")
        # Check that the `/` directory and the `session.root` directory are the same
        assert (expected.st_dev == result.st_dev) and (expected.st_ino == result.st_ino)

    def test_root_dir_remote(self):
        gdb = self._gdb
        gdb.execute("start")

        expected = os.stat("/")
        host = GDBSERVER_DEFAULT_HOST
        port = random.randint(1025, 65535)
        with gdbserver_session(port=port):
            gdb.execute(f"gef-remote {host} {port}")
            result = self._conn.root.eval("os.stat(gef.session.root)")
            assert (expected.st_dev == result.st_dev) and (
                expected.st_ino == result.st_ino
            )

    @pytest.mark.skipif(ARCH not in ("x86_64",), reason=f"Skipped for {ARCH}")
    def test_root_dir_qemu(self):
        gdb, gef = self._gdb, self._gef

        host = GDBSERVER_DEFAULT_HOST
        port = random.randint(1025, 65535)
        with qemuuser_session(port=port):
            gdb.execute(
                f"gef-remote --qemu-user --qemu-binary {self._target} {host} {port}"
            )
            assert re.search(r"\/proc\/[0-9]+/root", str(gef.session.root))
