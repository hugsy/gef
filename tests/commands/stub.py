"""
stub command test module
"""


import pytest
from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE


class StubCommand(RemoteGefUnitTestGeneric):
    """`stub` command test module"""

    @pytest.fixture(autouse=True)
    def capfd(self, capfd):
        self.capfd = capfd

    def test_cmd_stub(self):
        gdb = self._gdb
        # due to compiler optimizations printf might be converted to puts
        cmds = ("stub printf", "stub puts")
        for cmd in cmds:
            self.assertEqual(
                ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
            )

        #
        # Sanity Check - no exception
        #
        gdb.execute("start")
        captured = self.capfd.readouterr()
        gdb.execute("continue")
        captured = self.capfd.readouterr()

        assert "Hello World!" in captured.out

        #
        # Make sure the prints are stubbed out
        #
        gdb.execute("start")
        for cmd in cmds:
            gdb.execute(f"{cmd} --retval 42")
        assert len(gdb.breakpoints()) == len(cmds)

        #
        # Check again, make sure the stdout buffer is emptied
        #
        captured = self.capfd.readouterr()
        gdb.execute("continue")
        captured = self.capfd.readouterr()
        assert "Hello World!" not in captured.out
