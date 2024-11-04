"""
`target remote/extended-remote` test module.
"""


from tests.base import RemoteGefUnitTestGeneric
from tests.utils import debug_target, gdbserver_session, gdbserver_multi_session, get_random_port, qemuuser_session


class GefRemoteApi(RemoteGefUnitTestGeneric):

    def setUp(self) -> None:
        self._target = debug_target("default")
        return super().setUp()

    def test_gef_remote_test_gdbserver(self):
        """Test `gdbserver file`"""
        _gdb = self._gdb
        _root = self._conn.root
        port = get_random_port()

        with gdbserver_session(port=port):
            assert not _root.eval("is_target_remote()")
            assert not _root.eval("is_target_remote_or_extended()")
            assert not _root.eval("is_running_in_gdbserver()")

            _gdb.execute(f"target remote :{port}")

            assert _root.eval("is_target_remote()")
            assert _root.eval("is_target_remote_or_extended()")
            assert _root.eval("is_running_in_gdbserver()")

            assert not _root.eval("is_target_extended_remote()")
            assert not _root.eval("is_running_under_qemu()")
            assert not _root.eval("is_running_under_qemu_system()")
            assert not _root.eval("is_running_under_qemu_user()")
            assert not _root.eval("is_running_in_rr()")

    def test_gef_remote_test_gdbserver_multi(self):
        """Test `gdbserver --multi file`"""
        _gdb = self._gdb
        _root = self._conn.root
        port = get_random_port()

        with gdbserver_multi_session(port=port):
            assert not _root.eval("is_target_remote()")
            assert not _root.eval("is_target_remote_or_extended()")
            assert not _root.eval("is_running_in_gdbserver()")

            _gdb.execute(f"target extended-remote :{port}")

            assert _root.eval("is_target_remote()")
            assert _root.eval("is_target_remote_or_extended()")
            assert _root.eval("is_target_extended_remote()")
            assert _root.eval("is_running_in_gdbserver()")

            assert not _root.eval("is_running_under_qemu()")
            assert not _root.eval("is_running_under_qemu_system()")
            assert not _root.eval("is_running_under_qemu_user()")
            assert not _root.eval("is_running_in_rr()")

    def test_gef_remote_test_qemuuser(self):
        """Test `qemu-user -g`"""
        _gdb = self._gdb
        _root = self._conn.root
        port = get_random_port()

        with qemuuser_session(port=port):
            assert not _root.eval("is_target_remote()")
            assert not _root.eval("is_target_remote_or_extended()")
            assert not _root.eval("is_running_in_gdbserver()")

            _gdb.execute(f"target remote :{port}")

            assert _root.eval("is_target_remote()")
            assert _root.eval("is_target_remote_or_extended()")
            assert _root.eval("is_running_under_qemu()")
            assert _root.eval("is_running_under_qemu_user()")

            assert not _root.eval("is_target_extended_remote()")
            assert not _root.eval("is_running_under_qemu_system()")
            assert not _root.eval("is_running_in_gdbserver()")
            assert not _root.eval("is_running_in_rr()")

    # TODO add tests for
    #  - [ ] qemu-system
    #  - [ ] rr
