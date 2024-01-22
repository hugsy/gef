import pathlib
import unittest
import tempfile
import subprocess
import requests

import pytest

from tests.utils import GEF_PATH

SCRIPT_DIR = GEF_PATH.parent / "scripts"


class GefInstallScript(unittest.TestCase):
    def setUp(self):
        url = "https://api.github.com/repos/hugsy/gef/tags"
        res = requests.get(url)
        assert res.status_code == 200
        self.latest_release = res.json()[0]["name"]

    @pytest.mark.online
    def test_script_gef_sh(self):
        script_fpath = SCRIPT_DIR / "gef.sh"
        assert script_fpath.exists()

        # Execute the script within a mock home dir
        tempdir = tempfile.TemporaryDirectory()
        tempdir_path = pathlib.Path(tempdir.name)

        res = subprocess.call(
            ["sh", script_fpath], env={"HOME": str(tempdir_path.absolute())}
        )
        assert res == 0

        release = self.latest_release
        fname = f".gef-{release}.py"

        assert (tempdir_path / ".gdbinit").exists()
        assert (tempdir_path / ".gdbinit").open(
            "r", encoding="utf-8"
        ).read() == f"source ~/{fname}\n"

        fpath = tempdir_path / fname
        assert fpath.exists()
        assert len(fpath.open("rb").read()) > 0
