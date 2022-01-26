"""
unicorn-emulate command test module
"""


import pytest
from tests.utils import ARCH, GefUnitTestGeneric, _target, gdb_run_silent_cmd


class UnicornEmulateCommand(GefUnitTestGeneric):
    """`unicorn-emulate` command test module"""


    @pytest.mark.skipif(ARCH not in ["x86_64"], reason=f"Skipped for {ARCH}")
    def test_cmd_unicorn_emulate(self):
        nb_insn = 4
        cmd = f"emu {nb_insn}"
        res = gdb_run_silent_cmd(cmd)
        self.assertFailIfInactiveSession(res)

        target = _target("unicorn")
        before = ["break function1"]
        after = ["si"]
        start_marker = "= Starting emulation ="
        end_marker = "Final registers"
        res = gdb_run_silent_cmd(cmd, target=target, before=before, after=after)
        self.assertNoException(res)
        self.assertNotIn("Emulation failed", res)
        self.assertIn(start_marker, res)
        self.assertIn(end_marker, res)
        insn_executed = len(res[res.find(start_marker):res.find(end_marker)].splitlines()[1:-1])
        self.assertTrue(insn_executed >= nb_insn)