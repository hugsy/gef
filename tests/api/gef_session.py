"""
`gef.session` test module.
"""


import os
import random
import subprocess
from tests.utils import (
    TMPDIR,
    gdb_test_python_method,
    debug_target,
    GefUnitTestGeneric,
    gdbserver_session,
    gdb_run_cmd,
    qemuuser_session,
    GDBSERVER_DEFAULT_HOST
)
import re


class GefSessionApi(GefUnitTestGeneric):
    """`gef.session` test module."""

    def test_func_get_filepath(self):
        res = gdb_test_python_method("gef.session.file", target=debug_target("default"))
        self.assertNoException(res)
        target = TMPDIR / "foo bar"
        subprocess.call(["cp", debug_target("default"), target])
        res = gdb_test_python_method("gef.session.file", target=target)
        self.assertNoException(res)
        subprocess.call(["rm", target])


    def test_func_get_pid(self):
        res = gdb_test_python_method("gef.session.pid", target=debug_target("default"))
        self.assertNoException(res)
        self.assertTrue(int(res.splitlines()[-1]))


    def test_func_auxiliary_vector(self):
        func = "gef.session.auxiliary_vector"
        res = gdb_test_python_method(func, target=debug_target("default"))
        self.assertNoException(res)
        # we need at least ("AT_PLATFORM", "AT_EXECFN") right now
        self.assertTrue("'AT_PLATFORM'" in res)
        self.assertTrue("'AT_EXECFN':" in res)
        self.assertFalse("'AT_WHATEVER':" in res)

    def test_root_dir_local(self):
        func = "(s.st_dev, s.st_ino)"
        res = gdb_test_python_method(func, target=debug_target("default"), before="s=os.stat(gef.session.root)")
        self.assertNoException(res)
        st_dev, st_ino = eval(res.split("\n")[-1])
        stat_root = os.stat("/")
        # Check that the `/` directory and the `session.root` directory are the same
        assert (stat_root.st_dev == st_dev) and (stat_root.st_ino == st_ino)

    def test_root_dir_remote(self):
        func = "(s.st_dev, s.st_ino)"
        stat_root = os.stat("/")
        host = GDBSERVER_DEFAULT_HOST
        port = random.randint(1025, 65535)
        before = [f"gef-remote {host} {port}", "pi s=os.stat(gef.session.root)"]
        with gdbserver_session(port=port):
            res = gdb_run_cmd(f"pi {func}", target=debug_target("default"), before=before)
            self.assertNoException(res)
            st_dev, st_ino = eval(res.split("\n")[-1])
            assert (stat_root.st_dev == st_dev) and (stat_root.st_ino == st_ino)

    def test_root_dir_qemu(self):
        host = GDBSERVER_DEFAULT_HOST
        port = random.randint(1025, 65535)
        with qemuuser_session(port=port):
            target = debug_target("default")
            before = [
                f"gef-remote --qemu-user --qemu-binary {target} {host} {port}"]
            res = gdb_run_cmd(f"pi gef.session.root", target=debug_target("default"), before=before)
            self.assertNoException(res)
            assert re.search(r"\/proc\/[0-9]+/root", res)
