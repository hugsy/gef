"""
`smart_eval` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class SmartEvalCommand(GefUnitTestGeneric):
    """`smart_eval` command test module"""


    def test_cmd_smart_eval(self):
        examples = (
            ("$ $pc+1", "93824992235882\n0x55555555516a\n0b10101010101010101010101010101010101000101101010\nb'UUUUQj'\nb'jQUUUU'"),
            ("$ -0x1000", "-4096\n0xfffffffffffff000\n0b1111111111111111111111111111111111111111111111111111000000000000\nb'\\xff\\xff\\xff\\xff\\xff\\xff\\xf0\\x00'\nb'\\x00\\xf0\\xff\\xff\\xff\\xff\\xff\\xff'"),
            ("$ 0x00007ffff7812000 0x00007ffff79a7000", "1658880"),
            ("$ 1658880", "1658880\n0x195000\n0b110010101000000000000\nb'\\x19P\\x00'\nb'\\x00P\\x19'"),
        )
        for cmd, expected_value in examples:
            res = gdb_start_silent_cmd(cmd)
            self.assertNoException(res)
            self.assertIn(expected_value, res)
