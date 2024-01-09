"""
`smart_eval` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class SmartEvalCommand(RemoteGefUnitTestGeneric):
    """`smart_eval` command test module"""


    def test_cmd_smart_eval(self):
        gdb = self._gdb
        gef = self._gef

        gdb.execute("start")
        examples = (
            ("$ $pc+1", str(gef.arch.pc+1)),
            ("$ -0x1000", "-4096"),
            ("$ 0x00007ffff7812000 0x00007ffff79a7000", "1658880"),
            ("$ 1658880", "0b110010101000000000000"),
        )

        for cmd, expected_value in examples:
            res = gdb.execute(cmd, to_string=True).strip()
            self.assertIn(expected_value, res)
