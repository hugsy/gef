"""
virtualenv config test module
"""

from tests.base import RemoteGefUnitTestGeneric
from os import system
from tempfile import mktemp


class VirtualenvConfig(RemoteGefUnitTestGeneric):
    """virtualenv config test module"""

    def setUp(self) -> None:
        venv_path = mktemp()
        system(f"virtualenv {venv_path}")
        system(f"{venv_path}/bin/pip install numpy")

        self.venv_path = venv_path

        return super().setUp()

    def test_conf_venv(self):
        gdb = self._gdb
        gdb.execute(f"gef config gef.virtualenv_path {self.venv_path}")

        res = gdb.execute("pi __import__('numpy').test()", to_string=True)
        assert "NumPy version" in res
