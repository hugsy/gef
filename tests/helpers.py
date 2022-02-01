import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Union, NewType, List

TMPDIR = Path(tempfile.gettempdir())
DEFAULT_TARGET = TMPDIR / "default.out"
GEF_PATH = Path(os.getenv("GEF_PATH", "gef.py"))
STRIP_ANSI_DEFAULT = True
DEFAULT_CONTEXT = "-code -stack"
ARCH = (os.getenv("GEF_CI_ARCH") or platform.machine()).lower()
CI_VALID_ARCHITECTURES_32B = ("i686", "armv7l")
CI_VALID_ARCHITECTURES_64B = ("x86_64", "aarch64", "mips64el", "ppc64le", "riscv64")
CI_VALID_ARCHITECTURES = CI_VALID_ARCHITECTURES_64B + CI_VALID_ARCHITECTURES_32B
COVERAGE_DIR = os.getenv("COVERAGE_DIR", "")

CommandType = NewType("CommandType", Union[str, Iterable[str]])


def is_64b() -> bool:
    return ARCH in CI_VALID_ARCHITECTURES_64B


def ansi_clean(s: str) -> str:
    ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", s)


def _add_command(commands: CommandType) -> List[str]:
    if isinstance(commands, str):
        commands = [commands]
    return [_str for cmd in commands for _str in ["-ex", cmd]]


def gdb_run_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                target: Path = DEFAULT_TARGET, strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = ["gdb", "-q", "-nx"]
    if COVERAGE_DIR:
        coverage_file = Path(COVERAGE_DIR) / os.getenv("PYTEST_XDIST_WORKER")
        command += _add_command([
            "pi from coverage import Coverage",
            f"pi cov = Coverage(data_file=\"{coverage_file}\","
            "auto_data=True, branch=True)",
            "pi cov.start()",
        ])
    command += _add_command([
        f"source {GEF_PATH}",
        "gef config gef.debug True",
    ])
    command += _add_command(before)
    command += _add_command(cmd)
    command += _add_command(after)
    if COVERAGE_DIR:
        command += _add_command(["pi cov.stop()", "pi cov.save()"])
    command += ["-ex", "quit", "--", str(target)]

    lines = subprocess.check_output(command, stderr=subprocess.STDOUT).strip().splitlines()
    output = b"\n".join(lines)
    result = None

    # The following is necessary because ANSI escape sequences might have been
    # added in the middle of multibyte characters, e.g. \x1b[H\x1b[2J is added
    # into the middle of \xe2\x94\x80 to become \xe2\x1b[H\x1b[2J\x94\x80 which
    # causes a UnicodeDecodeError when trying to decode \xe2. Such broken
    # multibyte characters would need to be removed, otherwise the test will
    # result in an error.
    while not result:
        try:
            result = output.decode("utf-8")
        except UnicodeDecodeError as e:
            faulty_idx_start = int(e.start)
            faulty_idx_end = int(e.end)
            output = output[:faulty_idx_start] + output[faulty_idx_end:]

    if strip_ansi:
        result = ansi_clean(result)

    return result


def gdb_run_silent_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                       target: Path = DEFAULT_TARGET,
                       strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Disable the output and run entirely the `target` binary."""
    before = [*before, "gef config context.clear_screen False",
              "gef config context.layout '-code -stack'",
              "run"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_run_cmd_last_line(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                          target: Path = DEFAULT_TARGET,
                          strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_start_silent_cmd(cmd: CommandType, before: CommandType = (), after: CommandType = (),
                         target: Path = DEFAULT_TARGET,
                         strip_ansi: bool = STRIP_ANSI_DEFAULT,
                         context: str = DEFAULT_CONTEXT) -> str:
    """Execute a command in GDB by starting an execution context. This command
    disables the `context` and sets a tbreak at the most convenient entry
    point."""
    before = [*before, "gef config context.clear_screen False",
              f"gef config context.layout '{context}'",
              "entry-break"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_start_silent_cmd_last_line(cmd: CommandType, before: CommandType = (),
                                   after: CommandType = (),
                                   target: Path = DEFAULT_TARGET,
                                   strip_ansi=STRIP_ANSI_DEFAULT) -> str:
    """Execute `gdb_start_silent_cmd()` and return only the last line of its output."""
    return gdb_start_silent_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_test_python_method(meth: str, before: str = "", after: str = "",
                           target: Path = DEFAULT_TARGET,
                           strip_ansi: bool = STRIP_ANSI_DEFAULT) -> str:
    brk = before + ";" if before else ""
    cmd = f"pi {brk}print({meth});{after}"
    return gdb_start_silent_cmd(cmd, target=target, strip_ansi=strip_ansi)


def include_for_architectures(valid_architectures: Iterable[str] = CI_VALID_ARCHITECTURES):
    def wrapper(f):
        def inner_f(*args, **kwargs):
            if ARCH in valid_architectures:
                f(*args, **kwargs)
            else:
                sys.stderr.write(f"SKIPPED for {ARCH}  ")
                sys.stderr.flush()
        return inner_f
    return wrapper


def exclude_for_architectures(invalid_architectures: Iterable[str] = ()):
    def wrapper(f):
        def inner_f(*args, **kwargs):
            if ARCH not in invalid_architectures:
                f(*args, **kwargs)
            else:
                sys.stderr.write(f"SKIPPED for {ARCH}  ")
                sys.stderr.flush()
        return inner_f
    return wrapper


def _target(name: str, extension: str = ".out") -> Path:
    target = TMPDIR / f"{name}{extension}"
    if not target.exists():
        raise FileNotFoundError(f"Could not find file '{target}'")
    return target


def start_gdbserver(exe: Union[str, Path] = _target("default"),
                    port: int = 1234) -> subprocess.Popen:
    """Start a gdbserver on the target binary.

    Args:
        exe (str, optional): the binary to execute. Defaults to _target("default").
        port (int, optional): the port to make gdbserver listen on. Defaults to 1234.

    Returns:
        subprocess.Popen: a Popen object for the gdbserver process.
    """
    return subprocess.Popen(["gdbserver", f":{port}", exe],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_gdbserver(gdbserver: subprocess.Popen) -> None:
    """Stop the gdbserver and wait until it is terminated if it was
    still running. Needed to make the used port available again.

    Args:
        gdbserver (subprocess.Popen): the gdbserver process to stop.
    """
    if gdbserver.poll() is None:
        gdbserver.kill()
        gdbserver.wait()
    return