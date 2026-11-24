"""
`gef config` command test module
"""

from tests.base import RemoteGefUnitTestGeneric


class ConfigCommand(RemoteGefUnitTestGeneric):
    """`gef config` command test module"""

    cmd = "gef config"

    def test_cmd_config_unknown_prefix(self):
        """Reading a setting that does not exist must not fail silently."""
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd} nosuch.key", to_string=True)
        assert "No configuration setting matches 'nosuch.key'" in res

    def test_cmd_config_unknown_setting(self):
        """Setting a non-existent key of an existing plugin must be reported."""
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd} gef.debugg 1", to_string=True)
        assert "'gef.debugg' is not a valid configuration setting" in res

    def test_cmd_config_known_setting(self):
        """An existing setting still prints its description and value."""
        gdb = self._gdb
        res = gdb.execute(f"{self.cmd} gef.debug", to_string=True)
        assert "Enable debug mode for gef" in res
