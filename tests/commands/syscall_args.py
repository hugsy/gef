"""
`syscall-args` command test module
"""

import pathlib
import tempfile
import pytest

from tests.utils import (
    ARCH, GEF_DEFAULT_TEMPDIR,
    GefUnitTestGeneric, gdb_run_cmd,
    gdb_start_silent_cmd, _target,
    removeuntil, removeafter,
    download_file
)


@pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
class SyscallArgsCommand(GefUnitTestGeneric):
    """`syscall-args` command test module"""

    @pytest.mark.online
    def setUp(self) -> None:
        #
        # `syscall-args.out` only work for x86_64 and i686 architectures
        #
        self.tempdirfd = tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR)
        self.tempdirpath = pathlib.Path(self.tempdirfd.name).absolute()
        # download some syscall tables from gef-extras
        base = "https://raw.githubusercontent.com/hugsy/gef-extras/master/syscall-tables"
        # todo: maybe add "PowerPC", "PowerPC64", "SPARC", "SPARC64"
        for arch in ("ARM", "ARM_OABI", "X86", "X86_64"):
            url = f"{base}/{arch}.py"
            data = download_file(url)
            if not data:
                raise Exception(f"Failed to download {arch}.py ({url})")
            fpath = self.tempdirpath / f"{arch}.py"
            with fpath.open("wb") as fd:
                fd.write(data)
        return super().setUp()

    def tearDown(self) -> None:
        self.tempdirfd.cleanup()
        return


    def test_cmd_syscall_args(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("syscall-args"))
        before = (f"gef config syscall-args.path {self.tempdirpath.absolute()}",)
        after = ("continue", "syscall-args")
        res = gdb_start_silent_cmd("catch syscall openat",
                                   before=before,
                                   after=after,
                                   target=_target("syscall-args"),)
        self.assertNoException(res)
        self.assertIn("Detected syscall open", res)


@pytest.mark.skipif(ARCH not in ("i686", "x86_64"), reason=f"Skipped for {ARCH}")
class IsSyscallCommand(GefUnitTestGeneric):
    """`is-syscall` command test module"""

    def setUp(self) -> None:
        self.syscall_location = None
        res = gdb_run_cmd("disassemble openfile", target=_target("syscall-args"))
        start_str = "Dump of assembler code for function main:\n"
        end_str = "End of assembler dump."
        disass_code = removeafter(end_str, res)
        disass_code = removeuntil(start_str, disass_code)
        lines = disass_code.splitlines()
        for line in lines:
            parts = [x.strip() for x in line.split(maxsplit=3)]
            self.assertGreaterEqual(len(parts), 3)
            if ARCH == "x86_64" and parts[2] == "syscall":
                self.syscall_location = parts[1].lstrip('<').rstrip('>:')
                break
            if ARCH == "i686" and parts[2] == "int" and parts[3] == "0x80":
                self.syscall_location = parts[1].lstrip('<').rstrip('>:')
                break
        return super().setUp()


    def test_cmd_is_syscall(self):
        self.assertFailIfInactiveSession(gdb_run_cmd("is-syscall"))
        bp_loc = f"*(openfile{self.syscall_location})"
        res = gdb_run_cmd("is-syscall", target=_target("syscall-args"),
                          before=(f"break {bp_loc}", "run"),)
        self.assertNoException(res)
        self.assertIn("Current instruction is a syscall", res)
