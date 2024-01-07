"""
`reset-cache` command test module
"""


from tests.base import RemoteGefUnitTestGeneric


class ResetCacheCommand(RemoteGefUnitTestGeneric):
    """`reset-cache` command test module"""


    def test_cmd_reset_cache(self):
        gdb = self._gdb
        gdb.execute("start")
        res = gdb.execute("reset-cache", to_string=True)
        assert not res
        # TODO improve
