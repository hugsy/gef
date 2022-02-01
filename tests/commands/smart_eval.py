"""
`smart_eval` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_start_silent_cmd


class SmartEvalCommand(GefUnitTestGeneric):
    """`smart_eval` command test module"""


    def test_cmd_smart_eval(self):
        examples = (
            ("$ $pc+1", ""),
            ("$ -0x1000", "-4096"),
            ("$ 0x00007ffff7812000 0x00007ffff79a7000", "1658880"),
            ("$ 1658880", "0b110010101000000000000"),
        )
        for cmd, expected_value in examples:
            res = gdb_start_silent_cmd(cmd)
            self.assertNoException(res)
            self.assertIn(expected_value, res)
