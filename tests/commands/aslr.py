"""
`aslr` command test module
"""


from tests.utils import GefUnitTestGeneric, findlines, gdb_start_silent_cmd, removeuntil


class AslrCommand(GefUnitTestGeneric):
    """`aslr` command test module"""


    cmd = "aslr"


    def test_cmd_aslr_show(self):
        # show
        res = gdb_start_silent_cmd(self.cmd, after=("show disable-randomization",))
        self.assertNoException(res)
        self.assertIn("ASLR is currently ", res)
        self.assertEqual(res.count("ASLR is currently "), 1)

        # compare
        pattern = "ASLR is currently "
        cmd_output = removeuntil(pattern, findlines(pattern, res)[0])
        pattern = "virtual address space is "
        gdb_output = findlines(pattern, res)[0].split()[-1]
        if gdb_output == "on.":
            self.assertEqual(cmd_output, "disabled")
        else:
            self.assertEqual(cmd_output, "enabled")


    def test_cmd_aslr_toggle(self):
        # current value
        res = gdb_start_silent_cmd(self.cmd)
        pattern = "ASLR is currently "
        default_value = removeuntil(pattern, findlines(pattern, res)[0])

        # toggle
        if default_value == "enabled":
            res = gdb_start_silent_cmd(f"{self.cmd} off", after=(f"{self.cmd}"))
            cmd_output = removeuntil(pattern, findlines(pattern, res)[0])
            self.assertEqual(cmd_output, "disabled")
        elif default_value == "disabled":
            res = gdb_start_silent_cmd(f"{self.cmd} on", after=(f"{self.cmd}"))
            cmd_output = removeuntil(pattern, findlines(pattern, res)[0])
            self.assertEqual(cmd_output, "enabled")
        else:
            raise Exception(f"incorrect value: {default_value}")
