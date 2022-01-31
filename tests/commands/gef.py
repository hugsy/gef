"""
`gef` command test module
"""


from tests.utils import gdb_run_cmd, GefUnitTestGeneric


class GefCommand(GefUnitTestGeneric):
    """`gef` command test module"""


    def test_cmd_gef(self):
        res = gdb_run_cmd("gef")
        self.assertNoException(res)
        self.assertIn("GEF - GDB Enhanced Features", res)


    def test_cmd_gef_config(self):
        pass


    def test_cmd_gef_help(self):
        pass


    def test_cmd_gef_missing(self):
        pass


    def test_cmd_gef_restore(self):
        pass


    def test_cmd_gef_run(self):
        pass


    def test_cmd_gef_save(self):
        pass


    def test_cmd_gef_set(self):
        res = gdb_run_cmd("gef set args $_gef0", before=("pattern create -n 4", ), after=("show args"))
        self.assertNoException(res)
        self.assertIn("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaan", res)

        res = gdb_run_cmd("gef set args $_gef42", before=("pattern create -n 4", ), after=("show args"))
        self.assertException(res)
