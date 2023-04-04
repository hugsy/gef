"""
dereference command test module
"""


from tests.utils import gdb_run_cmd, gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class DereferenceCommand(GefUnitTestGeneric):
    """`dereference` command test module"""


    def test_cmd_dereference(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("dereference"))

        res = gdb_start_silent_cmd("dereference $sp")
        self.assertNoException(res)
        self.assertTrue(len(res.splitlines()) > 2)

        res = gdb_start_silent_cmd("dereference 0x0")
        self.assertNoException(res)
        self.assertIn("Unmapped address", res)


    def test_cmd_dereference_forwards(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("dereference"))

        cmd = "dereference $sp -l 2"
        setup = [
            "set {char[9]} ($sp+0x8) = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00 }",
            "set {char[9]} ($sp-0x8) = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00 }"
        ]
        res = gdb_start_silent_cmd(cmd=setup, after=cmd)
        self.assertNoException(res)

        """
        Assuming the default config of grow_stack_down = True, $sp should look like this:
        0x00007fffffffd278│+0x0008: "AAAAAAAA"
        0x00007fffffffd270│+0x0000: 0x0000000000000000   ← $rsp
        Hence, we want to look at the second last line of the output
        """
        res = res.splitlines()[-2]
        self.assertTrue("AAAAAAAA" in res)
        self.assertTrue("BBBBBBBB" not in res)


    def test_cmd_dereference_backwards(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("dereference"))

        cmd = "dereference $sp -l -2"
        setup = [
            "set {char[9]} ($sp+0x8) = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00 }",
            "set {char[9]} ($sp-0x8) = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00 }"
        ]
        res = gdb_start_silent_cmd(cmd=setup, after=cmd)
        self.assertNoException(res)

        """
        Assuming the default config of grow_stack_down = True, $sp should look like this:
        0x00007fffffffd270│+0x0000: 0x0000000000000000   ← $rsp
        0x00007fffffffd268│-0x0008: "BBBBBBBB"
        Hence, we want to look at the last line of the output
        """
        res = res.splitlines()[-1]
        self.assertTrue("AAAAAAAA" not in res)
        self.assertTrue("BBBBBBBB" in res)
