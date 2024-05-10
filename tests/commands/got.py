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
        self.assertNotIn("/libc", res)

        def checksyms(lines):
            if not lines:
                return None
            if "format-string-helper.out" in lines[0]:
                res = ''.join(lines)
                self.assertIn(" printf", res)
                self.assertNotIn(" strcpy", res)
                return "format-string-helper.out"
            if "/libc" in lines[0]:
                res = ''.join(lines)
                self.assertNotIn(" printf", res)
                self.assertNotIn(" strcpy", res)
                return "libc"
            return None

        res = gdb.execute("got --all printf", to_string=True)
        # Keep a list of output blocks describing files mapped in the process
        checked_sections = []
        # Iterate over lines of output and assemble blocks.  When a new block
        # is found, or when the end of output is reached, check the output
        # block for symbols expected in that block.
        lines = []
        for line in res.splitlines():
            if line.startswith("─"):
                checked_sections.append(checksyms(lines))
                lines = []
            lines.append(line)
        checked_sections.append(checksyms(lines))
        # Make sure that both the executable and libc sections were found.
        self.assertIn("format-string-helper.out", checked_sections)
        self.assertIn("libc", checked_sections)
