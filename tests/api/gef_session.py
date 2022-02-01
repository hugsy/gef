"""
`gef.session` test module.
"""


import subprocess
from tests.utils import (
    TMPDIR,
    gdb_test_python_method,
    _target,
    GefUnitTestGeneric,
)


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
