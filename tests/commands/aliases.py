"""
`aliases` command test module
"""

from tests.base import RemoteGefUnitTestGeneric


class AliasesCommand(RemoteGefUnitTestGeneric):
    """`aliases` command test module"""

    def test_cmd_aliases_add(self):
        gdb = self._gdb
        gef = self._gef

        initial_nb = len(gef.session.aliases)
        gdb.execute("aliases add alias_function_test example")
        assert initial_nb + 1 == len(gef.session.aliases)

    def test_cmd_aliases_list(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("aliases add alias_function_test example")
        # test list functionality
        list_res = gdb.execute("aliases ls", to_string=True)
        assert "alias_function_test" in list_res

        matches = [x for x in gef.session.aliases if x.alias == "alias_function_test"]
        assert len(matches) == 1
        assert matches[0].command == "example"

    def test_cmd_aliases_rm(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("aliases add alias_function_test example")
        matches = [x for x in gef.session.aliases if x.alias == "alias_function_test"]
        assert len(matches) == 1
        assert matches[0].command == "example"

        # test rm functionality
        gdb.execute("aliases rm alias_function_test")
        rm_res = gdb.execute("aliases ls", to_string=True).splitlines()
        assert any(map(lambda line: "alias_function_test" not in line, rm_res))

        matches = [x for x in gef.session.aliases if x.alias == "alias_function_test"]
        assert len(matches) == 0
