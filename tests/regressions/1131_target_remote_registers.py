import os
import pathlib
import tempfile

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import get_random_port, qemuuser_session

URL = "https://github.com/user-attachments/files/16913262/repr.zip"


@pytest.mark.slow
class MissingTargetRemoteRegisters(RemoteGefUnitTestGeneric):
    """@ref https://github.com/hugsy/gef/pull/1131"""

    def setUp(self) -> None:
        repro_script = f"""
        wget -O {{0}}/repr.zip {URL}
        unzip {{0}}/repr.zip -d {{0}}
        """

        self._tempdir = tempfile.TemporaryDirectory(prefix="gef-tests-")
        self._tempdir_path = pathlib.Path(self._tempdir.name)
        os.system(repro_script.format(self._tempdir_path))
        self._current_dir = self._tempdir_path / "repr"
        self._current_dir.mkdir(parents=True, exist_ok=True)
        self._previous_cwd = os.getcwd()
        os.chdir(self._current_dir)
        self._target = self._current_dir / "chal"
        # self._target.mkdir(exist_ok=True)
        return super().setUp()

    def tearDown(self) -> None:
        # Restore the original working directory if it was saved
        previous_cwd = getattr(self, "_previous_cwd", None)
        if previous_cwd is not None:
            os.chdir(previous_cwd)

        # Ensure the temporary directory is cleaned up
        tempdir = getattr(self, "_tempdir", None)
        if tempdir is not None:
            tempdir.cleanup()

        return super().tearDown()

    def test_target_remote_validate_post_hook_registers_display(self):
        _gdb = self._gdb
        _gef = self._gef
        port = get_random_port()

        # cmd: ./qemu-mipsel-static -g 1234 -L ./target ./chal
        with qemuuser_session(
            exe=self._target,
            port=port,
            qemu_exe=self._current_dir / "qemu-mipsel-static",
            args=["-L", str(self._current_dir / "target")],
        ):
            _gdb.execute(f"target remote :{port}")

            res = str(_gef.session.remote)
            assert (
                f"RemoteSession(target='localhost:{port}', local='/', mode=QEMU_USER)"
                in res
            )
