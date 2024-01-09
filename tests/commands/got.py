"""
`got` command test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric

from tests.utils import (
    ARCH,
    ERROR_INACTIVE_SESSION_MESSAGE,
    debug_target,
)


@pytest.mark.skipif(ARCH in ("ppc64le",), reason=f"Skipped for {ARCH}")
class GotCommand(RemoteGefUnitTestGeneric):
    """`got` command test module"""

    def setUp(self) -> None:
        self._target = debug_target("format-string-helper")
        return super().setUp()


    def test_cmd_got(self):
        gdb = self._gdb

        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE,gdb.execute("got", to_string=True))

        gdb.execute("start")
        res = gdb.execute("got", to_string=True)
        self.assertIn("printf", res)
        self.assertIn("strcpy", res)

        res = gdb.execute("got printf", to_string=True)
        self.assertIn("printf", res)
        self.assertNotIn("strcpy", res)
