"""
`aslr` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class AslrCommand(RemoteGefUnitTestGeneric):
    """`aslr` command test module"""

    cmd = "aslr"

    def __is_alsr_on_gdb(self):
        gdb = self._gdb
        gdb_output = gdb.execute("show disable-randomization", to_string=True).strip()
        return gdb_output.endswith("off.")  # i.e. disabled

    def test_cmd_aslr_show(self):
        gdb = self._gdb

        gef_output = gdb.execute(self.cmd, to_string=True).strip()

        # basic check
        if self.__is_alsr_on_gdb():
            assert gef_output == "ASLR is currently enabled"
        else:
            assert gef_output == "ASLR is currently disabled"

    def test_cmd_aslr_toggle(self):
        gdb = self._gdb

        # current value
        enabled = self.__is_alsr_on_gdb()

        # toggle
        if enabled:
            # switch off and check
            gdb.execute(f"{self.cmd} off")
            res = gdb.execute(self.cmd, to_string=True).strip()
            assert res == "ASLR is currently disabled"

        else:
            # switch on and check
            gdb.execute(f"{self.cmd} on")
            res = gdb.execute(self.cmd, to_string=True).strip()
            assert res == "ASLR is currently enabled"
