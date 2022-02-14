"""
set_permission command test module
"""

import pytest
import re

from tests.utils import (
    ARCH,
    GefUnitTestGeneric,
    _target,
    gdb_run_cmd,
    gdb_start_silent_cmd,
)


@pytest.mark.skipif(ARCH not in ("i686", "x86_64", "armv7l", "aarch64"),
                    reason=f"Skipped for {ARCH}")
class SetPermissionCommand(GefUnitTestGeneric):
    """`set_permission` command test module"""

    def setUp(self) -> None:
        try:
            import keystone # pylint: disable=W0611
        except ImportError:
            pytest.skip("keystone-engine not available", allow_module_level=True)
        return super().setUp()


    def test_cmd_set_permission(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("set-permission"))
        target = _target("set-permission")

        # get the initial stack address
        res = gdb_start_silent_cmd("vmmap", target=target)
        self.assertNoException(res)
        stack_line = [l.strip() for l in res.splitlines() if "[stack]" in l][0]
        stack_address = int(stack_line.split()[0], 0)

        # compare the new permissions
        res = gdb_start_silent_cmd(f"set-permission {stack_address:#x}",
                                   after=[f"xinfo {stack_address:#x}"], target=target)
        self.assertNoException(res)
        line = [l.strip() for l in res.splitlines() if l.startswith("Permissions: ")][0]
        self.assertEqual(line.split()[1], "rwx")

        res = gdb_start_silent_cmd("set-permission 0x1338000", target=target)
        self.assertNoException(res)
        self.assertIn("Unmapped address", res)

        # Make sure set-permission command doesn't clobber any register
        before = [
            "gef config context.clear_screen False",
            "gef config context.layout '-code -stack'",
            "entry-break",
            "printf \"match_before\\n\"",
            "info registers all",
            "printf \"match_before\\n\""
        ]
        after = [
            "printf \"match_after\\n\"",
            "info registers all",
            "printf \"match_after\\n\""
        ]
        res = gdb_run_cmd("set-permission $sp", before=before, after=after, target=target)
        matches = re.match(r"(?:.*match_before)(.+)(?:match_before.*)", res, flags=re.DOTALL)
        if not matches:
            raise Exception("Unexpected output")
        regs_before = matches[1]
        matches = re.match(r"(?:.*match_after)(.+)(?:match_after.*)", res, flags=re.DOTALL)
        if not matches:
            raise Exception("Unexpected output")
        regs_after = matches[1]
        self.assertEqual(regs_before, regs_after)
