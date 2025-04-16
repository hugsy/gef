import os
import pathlib
import re
import subprocess
import tempfile
import time

import unittest

import rpyc

from .utils import debug_target, get_random_port, which

COVERAGE_DIR = os.getenv("COVERAGE_DIR", "")
GEF_PATH = pathlib.Path(os.getenv("GEF_PATH", "gef.py")).absolute()
RPYC_GEF_PATH = GEF_PATH.parent / "scripts/remote_debug.py"
RPYC_HOST = "localhost"
RPYC_PORT = 18812
RPYC_SPAWN_TIME = 1.0
RPYC_MAX_REMOTE_CONNECTION_ATTEMPTS = 5
GDB_BINARY_PATH = which("gdb-multiarch")
RPYC_CONNECT_FAILURE_DELAY = 0.2


class RemoteGefUnitTestGeneric(unittest.TestCase):
    """
    The base class for GEF test cases. This will create the `rpyc` environment to programmatically interact with
    GDB and GEF in the test.
    """

    def setUp(self) -> None:
        self._gdb_path = GDB_BINARY_PATH
        attempt = RPYC_MAX_REMOTE_CONNECTION_ATTEMPTS
        while True:
            try:
                #
                # Port collisions can happen, allow a few retries
                #
                self._coverage_file = None
                self.__setup()
                break
            except ConnectionRefusedError:
                attempt -= 1
                if attempt == 0:
                    raise
                time.sleep(RPYC_CONNECT_FAILURE_DELAY)
                continue

        self._gdb = self._conn.root.gdb
        self._gef = self._conn.root.gef
        return super().setUp()

    def __setup(self):
        if not hasattr(self, "_target"):
            setattr(self, "_target", debug_target("default"))
        else:
            assert isinstance(self._target, pathlib.Path)  # type: ignore pylint: disable=E1101
            assert self._target.exists()  # type: ignore pylint: disable=E1101

        #
        # Select a random tcp port for rpyc
        #
        self._port = get_random_port()
        self._commands = ""

        if COVERAGE_DIR:
            self._coverage_file = pathlib.Path(COVERAGE_DIR) / os.getenv(
                "PYTEST_XDIST_WORKER", "gw0"
            )
            self._commands += f"""
pi import coverage
pi cov = coverage.Coverage(data_file="{self._coverage_file}", auto_data=True, branch=True)
pi cov.start()
"""

        self._commands += f"""
source {GEF_PATH}
gef config gef.debug True
gef config gef.propagate_debug_exception True
gef config gef.disable_color True
source {RPYC_GEF_PATH}
pi start_rpyc_service({self._port})
"""

        self._initfile = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self._initfile.write(self._commands)
        self._initfile.flush()
        self._command = [
            GDB_BINARY_PATH,
            "-q",
            "-nx",
            "-ex",
            f"source {self._initfile.name}",
            "--",
            str(self._target.absolute()),  # type: ignore pylint: disable=E1101
        ]

        self._process = subprocess.Popen(self._command)
        assert self._process.pid > 0
        time.sleep(RPYC_SPAWN_TIME)
        self._conn = rpyc.connect(
            RPYC_HOST,
            self._port,
        )

    def tearDown(self) -> None:
        if COVERAGE_DIR:
            self._gdb.execute("pi cov.stop()")
            self._gdb.execute("pi cov.save()")
        self._conn.close()
        self._process.terminate()
        return super().tearDown()

    @property
    def gdb_version(self) -> tuple[int, int]:
        res = re.search(r"(\d+)\D(\d+)", self._gdb.VERSION)
        assert res
        groups = [int(d) for d in res.groups()]
        assert len(groups) == 2
        return groups[0], groups[1]
