"""
`gef tmux-split` command and per-section context redirection test module.
"""

import os
import tempfile

from tests.base import RemoteGefUnitTestGeneric


class TmuxSplitCommand(RemoteGefUnitTestGeneric):
    """`gef tmux-split` command test module"""

    def test_per_section_redirect_routes_output(self):
        """Setting `context.output.regs` to a file makes the regs section render there
        instead of stdout. The other sections should still appear on stdout."""
        gdb = self._gdb

        with tempfile.NamedTemporaryFile(mode="r", suffix=".tty", delete=False) as f:
            redirect_path = f.name

        try:
            gdb.execute("start")
            gdb.execute(f"gef config context.output.regs {redirect_path}")
            stdout_buf = gdb.execute("context", to_string=True) or ""

            with open(redirect_path) as fd:
                pane_buf = fd.read()

            assert "registers" in pane_buf
            assert "registers" not in stdout_buf
        finally:
            gdb.execute("gef config context.output.regs ''")
            os.unlink(redirect_path)

    def test_per_section_redirect_recovers_when_file_missing(self):
        """If the redirect target disappears, GEF should clear the setting and not crash."""
        gdb = self._gdb
        gef = self._gef

        bogus = "/tmp/gef-tmux-split-test-does-not-exist"
        if os.path.exists(bogus):
            os.unlink(bogus)
        os.mkdir(bogus)  # make the open() fail with EISDIR

        try:
            gdb.execute("start")
            gdb.execute(f"gef config context.output.regs {bogus}")
            gdb.execute("context", to_string=True)
            assert gef.config["context.output.regs"] == ""
        finally:
            os.rmdir(bogus)

    def test_tmux_split_outside_tmux_errors(self):
        """Running `gef tmux-split` outside a tmux session must error and not modify state."""
        gdb = self._gdb
        gef = self._gef

        # ensure the env var is unset for the spawned gdb's subprocess view; rpyc-bridged exec
        # inherits the gdb process env, so toggle via `set environment`.
        gdb.execute("unset environment TMUX")

        out = gdb.execute("gef tmux-split", to_string=True) or ""
        assert "Not in a tmux session" in out
        assert len(gef.session.tmux_panes) == 0

    def test_tmux_split_reset_clears_settings(self):
        """`--reset` must clear all `context.output.*` settings even with no panes spawned."""
        gdb = self._gdb
        gef = self._gef

        gdb.execute("gef config context.output.regs /tmp/nope-1")
        gdb.execute("gef config context.output.stack /tmp/nope-2")
        gdb.execute("gef tmux-split --reset")

        assert gef.config["context.output.regs"] == ""
        assert gef.config["context.output.stack"] == ""
        assert len(gef.session.tmux_panes) == 0

    def test_per_section_settings_registered(self):
        """All known sections must have a `context.output.<section>` setting registered."""
        gef = self._gef
        for section in (
            "legend",
            "regs",
            "stack",
            "code",
            "args",
            "memory",
            "source",
            "trace",
            "threads",
            "extra",
        ):
            assert f"context.output.{section}" in gef.config

    def _run_parser(self, ini_text: str) -> str:
        """Drive `_parse_tmux_layout_ini` inside the spawned GDB and return either
        'OK:<n_panes>:<first_name>' or 'ERR:<message>'. Uses a /tmp helper script so we
        don't have to wrestle with GDB's `pi` line-continuation rules."""
        gdb = self._gdb
        ini_file = tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False)
        ini_file.write(ini_text)
        ini_file.close()
        helper = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        helper.write(
            "import pathlib\n"
            f"_p = pathlib.Path({ini_file.name!r})\n"
            "try:\n"
            "    _ps = _parse_tmux_layout_ini(_p, GefTmuxSplitCommand.KNOWN_SECTIONS)\n"
            "    _result = 'OK:' + str(len(_ps)) + ':' + _ps[0].name\n"
            "except ValueError as _e:\n"
            "    _result = 'ERR:' + str(_e)\n"
        )
        helper.close()
        gdb.execute(f"pi exec(open({helper.name!r}).read())")
        out = gdb.execute("pi print(_result)", to_string=True) or ""
        os.unlink(ini_file.name)
        os.unlink(helper.name)
        return out.strip()

    def test_layout_parser_accepts_pwndbg_classic(self):
        gdb = self._gdb
        gdb.execute("pi _ini_text = PWNDBG_CLASSIC_LAYOUT_INI")
        ini_text = (gdb.execute("pi print(_ini_text)", to_string=True) or "").strip()
        assert "[layout]" in ini_text
        result = self._run_parser(ini_text)
        # 4 panes (regs/stack/code/trace), regs first.
        assert result == "OK:4:regs", result

    def test_layout_parser_rejects_unknown_section(self):
        bad = (
            "[layout]\npanes = a\n"
            "[pane.a]\nsection = not_a_real_section\ndirection = right\n"
        )
        result = self._run_parser(bad)
        assert result.startswith("ERR:")
        assert "not_a_real_section" in result

    def test_layout_parser_rejects_forward_reference(self):
        # `b` references `a` but is declared before it in [layout].panes.
        bad = (
            "[layout]\npanes = b, a\n"
            "[pane.a]\nsection = regs\ndirection = right\n"
            "[pane.b]\nsection = stack\ndirection = below\nrelative_to = a\n"
        )
        result = self._run_parser(bad)
        assert "has not been declared yet" in result

    def test_layout_parser_rejects_duplicate_section(self):
        bad = (
            "[layout]\npanes = a, b\n"
            "[pane.a]\nsection = regs\ndirection = right\n"
            "[pane.b]\nsection = regs\ndirection = below\nrelative_to = a\n"
        )
        result = self._run_parser(bad)
        assert "more than one pane" in result

    def test_layout_parser_rejects_bad_direction(self):
        bad = "[layout]\npanes = a\n[pane.a]\nsection = regs\ndirection = sideways\n"
        result = self._run_parser(bad)
        assert "direction" in result

    def test_dump_layout_writes_file(self):
        gdb = self._gdb
        # Reserve a unique path without creating the file (so --dump-layout writes it).
        fd, path = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        os.unlink(path)
        try:
            gdb.execute(f"gef tmux-split --dump-layout pwndbg-classic {path}")
            assert os.path.exists(path)
            content = open(path).read()
            assert "[layout]" in content
            assert "panes =" in content
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_dump_layout_refuses_overwrite(self):
        gdb = self._gdb
        existing = tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False)
        existing.write("PRE-EXISTING\n")
        existing.close()
        try:
            gdb.execute(f"gef tmux-split --dump-layout pwndbg-classic {existing.name}")
            # File should be untouched
            assert open(existing.name).read() == "PRE-EXISTING\n"
        finally:
            os.unlink(existing.name)
