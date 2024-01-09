"""
Shellcode commands test module
"""
import pytest
from tests.base import RemoteGefUnitTestGeneric

from tests.utils import BIN_SH


class ShellcodeCommand(RemoteGefUnitTestGeneric):
    """`shellcode` command test module"""

    def test_cmd_shellcode(self):
        gdb = self._gdb
        gdb.execute("start")
        res = gdb.execute("shellcode", to_string=True)
        self.assertIn("Missing sub-command (search|get)", res)

    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_search(self):
        gdb = self._gdb
        cmd = f"shellcode search execve {BIN_SH}"
        gdb.execute("start")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn(f"setuid(0) + execve({BIN_SH}) 49 bytes", res)

    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_get_ok(self):
        gdb = self._gdb
        gdb.execute("start")
        res = gdb.execute("shellcode get 77", to_string=True)
        self.assertIn("Shellcode written to ", res)

    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_get_nok(self):
        gdb = self._gdb
        n = 1111111111111
        gdb.execute("start")
        res = gdb.execute(f"shellcode get {n}", to_string=True)
        self.assertIn(f"Failed to fetch shellcode #{n}", res)
