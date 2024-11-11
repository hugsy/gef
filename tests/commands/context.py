"""
`context` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class ContextCommand(RemoteGefUnitTestGeneric):
    """`context` command test module"""


    cmd = "context"


    # TODO See https://github.com/hugsy/gef/projects/10

    def test_duplicate_pane_name(self):
        # Make sure we cannot have 2 context panes with an identical identifier
        # See #1145 , #1153
        gdb = self._gdb
        gef = self._gef

        new_pane_id = "new_pane1"
        current_layout = gef.config["context.layout"]
        assert not current_layout.endswith(new_pane_id)

        res = gdb.execute(f"pi register_external_context_pane('{new_pane_id}', print, print, None)", to_string=True)
        assert "Python Exception" not in res
        new_layout = gef.config["context.layout"]
        assert new_layout.endswith(new_pane_id)

        res = gdb.execute(f"pi register_external_context_pane('{new_pane_id}', print, print, None)", to_string=True)
        assert "Python Exception" not in res
        new_layout2 = gef.config["context.layout"]
        assert new_layout == new_layout2
        assert f"Duplicate name for `{new_pane_id}`" in res
