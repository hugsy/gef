"""
`gef` command test module
"""

import pytest
import pathlib

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import removeuntil


class GefCommand(RemoteGefUnitTestGeneric):
    """`gef` command test module"""

    def test_cmd_gef(self):
        gdb = self._gdb
        res = gdb.execute("gef", to_string=True)
        self.assertIn("GEF - GDB Enhanced Features", res)

    def test_cmd_gef_config(self):
        gdb = self._gdb
        res = gdb.execute("gef config", to_string=True)
        self.assertIn("GEF configuration settings", res)

        known_patterns = (
            "gef.autosave_breakpoints_file (str)",
            "gef.debug (bool)",
            "gef.disable_color (bool)",
            "gef.extra_plugins_dir (str)",
            "gef.follow_child (bool)",
            "gef.readline_compat (bool)",
            "gef.show_deprecation_warnings (bool)",
            "gef.tempdir (Path)",
            "got.function_not_resolved (str)",
            "got.function_resolved (str)",
        )
        for pattern in known_patterns:
            self.assertIn(pattern, res)

    def test_cmd_gef_config_get(self):
        gdb = self._gdb
        res = gdb.execute("gef config gef.debug", to_string=True)
        self.assertIn("GEF configuration setting: gef.debug", res)
        self.assertIn(
            """gef.debug (bool) = True\n\nDescription:\n\tEnable debug mode for gef""",
            res,
        )

    def test_cmd_gef_config_set(self):
        gdb = self._gdb
        root = self._conn.root

        gdb.execute("gef config gef.debug 1")
        assert root.eval("is_debug()")

        gdb.execute("gef config gef.debug 0")
        assert not root.eval("is_debug()")

    def test_cmd_gef_help(self):
        gdb = self._gdb
        res = gdb.execute("help gef", to_string=True)
        known_patterns = (
            "gef config",
            "gef help",
            "gef install",
            "gef missing",
            "gef restore",
            "gef run",
            "gef save",
            "gef set",
        )
        for pattern in known_patterns:
            self.assertIn(pattern, res)

    def test_cmd_gef_run_and_run(self):
        gdb = self._gdb

        # valid
        pattern = gdb.execute("pattern create -n 4", to_string=True).splitlines()[1]
        assert len(pattern) == 1024, f"Unexpected pattern length {len(pattern)}"
        res = gdb.execute("gef set args $_gef0")
        res = gdb.execute("show args", to_string=True).strip()
        assert (
            res
            == f'Argument list to give program being debugged when it is started is "{pattern}".'
        )

        # invalid
        with pytest.raises(Exception):
            gdb.execute("gef set args $_gef42")

    def test_cmd_gef_save(self):
        root = self._conn.root
        gdb = self._gdb

        # check
        res = gdb.execute("gef save", to_string=True).strip()
        self.assertIn("Configuration saved to '", res)

        gefrc_file = removeuntil("Configuration saved to '", res.rstrip("'"))
        assert gefrc_file == root.eval("str(GEF_RC)")

        # set & check
        for name in ("AAAABBBBCCCCDDDD", "gef"):
            gdb.execute(f"gef config gef.tempdir /tmp/{name}")
            res = gdb.execute("gef save")
            with pathlib.Path(gefrc_file).open() as f:
                config = f.read()
                self.assertIn(f"tempdir = /tmp/{name}\n", config)

    @pytest.mark.online
    def test_cmd_gef_install(self):
        gdb = self._gdb
        test_commands = ("skel", "windbg", "stack")
        res = gdb.execute(f"gef install {' '.join(test_commands)}", to_string=True)
        # we install 3 plugins, the pattern must be found 3 times
        pattern = "Installed file"
        for i in range(len(test_commands)):
            idx = res.find(pattern)
            self.assertNotEqual(
                -1, idx, f"Check {i}/{3} failed: missing '{pattern}' in\n{res}"
            )
            self.assertIn("new command(s) available", res)
            res = res[idx:]
