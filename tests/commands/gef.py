"""
`gef` command test module
"""

import pytest
import pathlib

from tests.utils import (
    gdb_run_cmd,
    GefUnitTestGeneric,
    gdb_start_silent_cmd_last_line,
    removeuntil,
)


class GefCommand(GefUnitTestGeneric):
    """`gef` command test module"""


    def test_cmd_gef(self):
        res = gdb_run_cmd("gef")
        self.assertNoException(res)
        self.assertIn("GEF - GDB Enhanced Features", res)


    def test_cmd_gef_config(self):
        res = gdb_run_cmd("gef config")
        self.assertNoException(res)
        self.assertIn("GEF configuration settings", res)

        known_patterns = (
            "gef.autosave_breakpoints_file (str)",
            "gef.debug (bool)",
            "gef.disable_color (bool)",
            "gef.extra_plugins_dir (str)",
            "gef.follow_child (bool)",
            "gef.readline_compat (bool)",
            "gef.show_deprecation_warnings (bool)",
            "gef.tempdir (str)",
            "got.function_not_resolved (str)",
            "got.function_resolved (str)",
        )
        for pattern in known_patterns:
            self.assertIn(pattern, res)


    def test_cmd_gef_config_get(self):
        res = gdb_run_cmd("gef config gef.debug")
        self.assertNoException(res)
        self.assertIn("GEF configuration setting: gef.debug", res)
        # the `True` is automatically set by `gdb_run_cmd` so we know it's there
        self.assertIn("""gef.debug (bool) = True\n\nDescription:\n\tEnable debug mode for gef""",
                      res)


    def test_cmd_gef_config_set(self):
        res = gdb_start_silent_cmd_last_line("gef config gef.debug 0",
                                             after=("pi print(is_debug())", ))
        self.assertNoException(res)
        self.assertEqual("False", res)


    def test_cmd_gef_help(self):
        res = gdb_run_cmd("help gef")
        self.assertNoException(res)

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
        res = gdb_run_cmd("gef set args $_gef0",
                          before=("pattern create -n 4", ),
                          after=("show args"))
        self.assertNoException(res)
        self.assertIn("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaan", res)

        res = gdb_run_cmd("gef set args $_gef42",
                          before=("pattern create -n 4", ),
                          after=("show args"))
        self.assertException(res)


    def test_cmd_gef_save(self):
        # check
        res = gdb_run_cmd("gef save")
        self.assertNoException(res)
        self.assertIn("Configuration saved to '", res)

        gefrc_file = removeuntil("Configuration saved to '", res.rstrip("'"))

        # set & check
        for name in ("AAAABBBBCCCCDDDD", "gef"):
            res = gdb_run_cmd("gef save", before=(f"gef config gef.tempdir /tmp/{name}", ))
            self.assertNoException(res)
            with pathlib.Path(gefrc_file).open() as f:
                config = f.read()
                self.assertIn(f'tempdir = /tmp/{name}\n', config)


    @pytest.mark.online
    def test_cmd_gef_install(self):
        test_commands = ("skel", "windbg", "stack")
        res = gdb_run_cmd(f"gef install {' '.join(test_commands)}")
        self.assertNoException(res)
        # we install 3 plugins, the pattern must be found 3 times
        pattern = "Installed file"
        for i in range(len(test_commands)):
            idx = res.find(pattern)
            self.assertNotEqual(-1,  idx, f"Check {i}/{3} failed: missing '{pattern}' in\n{res}")
            self.assertIn("new command(s) available", res)
            res = res[idx:]
