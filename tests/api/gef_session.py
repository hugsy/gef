"""
`gef.session` test module.
"""


from logging import root
import subprocess
import os
from tests.utils import (
    TMPDIR,
    gdb_test_python_method,
    _target,
    GefUnitTestGeneric,
    gdbserver_session,
    gdb_run_cmd,
    qemuuser_session
)
import re

GDBSERVER_PREFERED_HOST = "localhost"
GDBSERVER_PREFERED_PORT = 1234

class GefSessionApi(GefUnitTestGeneric):
    """`gef.session` test module."""


    def test_func_get_filepath(self):
        res = gdb_test_python_method("gef.session.file", target=_target("default"))
        self.assertNoException(res)
        target = TMPDIR / "foo bar"
        subprocess.call(["cp", _target("default"), target])
        res = gdb_test_python_method("gef.session.file", target=target)
        self.assertNoException(res)
        subprocess.call(["rm", target])


    def test_func_get_pid(self):
        res = gdb_test_python_method("gef.session.pid", target=_target("default"))
        self.assertNoException(res)
        self.assertTrue(int(res.splitlines()[-1]))


    def test_func_auxiliary_vector(self):
        func = "gef.session.auxiliary_vector"
        res = gdb_test_python_method(func, target=_target("default"))
        self.assertNoException(res)
        # we need at least ("AT_PLATFORM", "AT_EXECFN") right now
        self.assertTrue("'AT_PLATFORM'" in res)
        self.assertTrue("'AT_EXECFN':" in res)
        self.assertFalse("'AT_WHATEVER':" in res)

    def test_root_dir(self):
        func = "(s.st_dev, s.st_ino)"
        res = gdb_test_python_method(func, target=_target("default"), before="s=os.stat(gef.session.root)")
        self.assertNoException(res)
        st_dev, st_ino = eval(res.split("\n")[-1])
        stat_root = os.stat("/")
        # Check that the `/` directory and the `session.root` directory are the same
        assert (stat_root.st_dev == st_dev) and (stat_root.st_ino == st_ino)

        port = GDBSERVER_PREFERED_PORT + 1
        before = [f"gef-remote {GDBSERVER_PREFERED_HOST} {port}",
                   "pi s = os.stat(gef.session.root)"]
        with gdbserver_session(port=port) as _:
            res = gdb_run_cmd(f"pi {func}", target=_target("default"), before=before)
            self.assertNoException(res)
            st_dev, st_ino = eval(res.split("\n")[-1])
            assert (stat_root.st_dev == st_dev) and (stat_root.st_ino == st_ino)

        port = GDBSERVER_PREFERED_PORT + 2
        with qemuuser_session(port=port) as _:
            target = _target("default")
            before = [
                f"gef-remote --qemu-user --qemu-binary {target} {GDBSERVER_PREFERED_HOST} {port}"]
            res = gdb_run_cmd(f"pi gef.session.root", target=_target("default"), before=before)
            self.assertNoException(res)
            assert re.search(r"\/proc\/[0-9]+/root", res)
