"""
`gef.session` test module.
"""

import pathlib
import os
import random

from tests.utils import (
    debug_target,
    RemoteGefUnitTestGeneric,
    gdbserver_session,
    qemuuser_session,
    GDBSERVER_DEFAULT_HOST,
)
import re


class GefSessionApi(RemoteGefUnitTestGeneric):
    """`gef.session` test module."""

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

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

    def test_root_dir_qemu(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("start")

        host = GDBSERVER_DEFAULT_HOST
        port = random.randint(1025, 65535)
        with qemuuser_session(port=port):
            gdb.execute(
                f"gef-remote --qemu-user --qemu-binary {self._target} {host} {port}"
            )
            assert re.search(r"\/proc\/[0-9]+/root", str(gef.session.root))
