"""
`aliases` command test module
"""


from tests.utils import gdb_start_silent_cmd
from tests.utils import GefUnitTestGeneric


class AliasesCommand(GefUnitTestGeneric):
    """`aliases` command test module"""

    def test_cmd_aliases(self):
        # test add functionality
        add_res = gdb_start_silent_cmd("aliases add alias_function_test example")
        self.assertNoException(add_res)
        # test list functionality
        list_res = gdb_start_silent_cmd("aliases ls",
                                        before=["aliases add alias_function_test example"])
        self.assertNoException(list_res)
        self.assertIn("alias_function_test", list_res)
        # test rm functionality
        rm_res = gdb_start_silent_cmd("aliases ls",
                                      before=["aliases add alias_function_test example",
                                              "aliases rm alias_function_test"])
        self.assertNoException(rm_res)
        self.assertNotIn("alias_function_test", rm_res)
