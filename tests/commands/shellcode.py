"""
Shellcode commands test module
"""
import pytest

from tests.utils import gdb_start_silent_cmd, GefUnitTestGeneric, BIN_SH


class ShellcodeCommand(GefUnitTestGeneric):
    """`shellcode` command test module"""

    def test_cmd_shellcode(self):
        res = gdb_start_silent_cmd("shellcode")
        self.assertNoException(res)
        self.assertIn("Missing sub-command (search|get)", res)


    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_search(self):
        cmd = f"shellcode search execve {BIN_SH}"
        res = gdb_start_silent_cmd(cmd)
        self.assertNoException(res)
        self.assertIn(f"setuid(0) + execve({BIN_SH}) 49 bytes", res)


    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_get_ok(self):
        res = gdb_start_silent_cmd("shellcode get 77")
        self.assertNoException(res)
        self.assertIn("Shellcode written to ", res)


    @pytest.mark.online
    @pytest.mark.slow
    def test_cmd_shellcode_get_nok(self):
        n = 1111111111111
        res = gdb_start_silent_cmd(f"shellcode get {n}")
        self.assertNoException(res)
        self.assertIn(f"Failed to fetch shellcode #{n}", res)
