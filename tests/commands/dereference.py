"""
dereference command test module
"""

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class DereferenceCommand(RemoteGefUnitTestGeneric):
    """`dereference` command test module"""

    def test_cmd_dereference(self):
        gdb = self._gdb

        assert (
            gdb.execute("dereference", to_string=True) == ERROR_INACTIVE_SESSION_MESSAGE
        )

        gdb.execute("start")

        res = gdb.execute("dereference $sp", to_string=True)
        self.assertTrue(len(res.splitlines()) > 2)

        res = gdb.execute("dereference 0x0", to_string=True)
        self.assertIn("Unmapped address", res)

    def test_cmd_dereference_forwards(self):
        gdb = self._gdb

        assert (
            gdb.execute("dereference", to_string=True) == ERROR_INACTIVE_SESSION_MESSAGE
        )

        gdb.execute("start")

        for setup in [
            "gef config context.grow_stack_down False",
            "set {char[9]} ($sp+0x8) = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00 }",
            "set {char[9]} ($sp-0x8) = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00 }",
        ]:
            gdb.execute(setup)

        cmd = "dereference $sp -l 2"
        res = gdb.execute(cmd, to_string=True)

        """
        Assuming the default config of grow_stack_down = False, $sp should look like this:
        0x00007fffffffd270│+0x0000: 0x0000000000000000   ← $rsp
        0x00007fffffffd278│+0x0008: "AAAAAAAA"
        Hence, we want to look at the last line of the output
        """
        res = res.splitlines()[-1]
        assert "AAAAAAAA" in res
        assert "BBBBBBBB" not in res

    def test_cmd_dereference_backwards(self):
        gdb = self._gdb

        assert (
            gdb.execute("dereference", to_string=True) == ERROR_INACTIVE_SESSION_MESSAGE
        )

        gdb.execute("start")

        for setup in [
            "gef config context.grow_stack_down False",
            "set {char[9]} ($sp+0x8) = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00 }",
            "set {char[9]} ($sp-0x8) = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00 }",
        ]:
            gdb.execute(setup)

        cmd = "dereference $sp -l -2"
        res = gdb.execute(cmd, to_string=True)

        """
        Assuming the default config of grow_stack_down = False, $sp should look like this:
        0x00007fffffffd268│-0x0008: "BBBBBBBB"
        0x00007fffffffd270│+0x0000: 0x0000000000000000   ← $rsp
        Hence, we want to look at the second last line of the output
        """
        res = res.splitlines()[-2]
        assert "AAAAAAAA" not in res
        assert "BBBBBBBB" in res
