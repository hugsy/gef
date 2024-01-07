"""
xor-memory command test module
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import ERROR_INACTIVE_SESSION_MESSAGE

class XorMemoryCommand(RemoteGefUnitTestGeneric):
    """`xor-memory` command test module"""


    def test_cmd_xor_memory_display(self):
        gdb = self._gdb
        cmd = "xor-memory display $sp 0x10 0x41"
        self.assertEqual(ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True))

        gdb.execute("start")
        res = gdb.execute(cmd)
        assert "Original block" in res
        assert "XOR-ed block" in res


    def test_cmd_xor_memory_patch(self):
        gdb = self._gdb
        gdb.execute("start")

        cmd = "xor-memory patch $sp 0x10 0x41"
        res = gdb.execute(cmd, to_string=True)
        assert "Patching XOR-ing " in res
