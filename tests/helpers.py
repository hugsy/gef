import re
import subprocess

PATH_TO_DEFAULT_BINARY = "/tmp/default.out"
STRIP_ANSI_DEFAULT = True

def ansi_clean(s):
    ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", s)


def gdb_run_cmd(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY, strip_ansi=STRIP_ANSI_DEFAULT):
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = [
        "gdb", "-q", "-nx",
        "-ex", "source /tmp/gef.py",
        "-ex", "gef config gef.debug True"
    ]

    if before:
        for _ in before: command += ["-ex", _]

    command += ["-ex", cmd]

    if after:
        for _ in after: command += ["-ex", _]

    command += ["-ex", "quit", "--", target]

    lines = subprocess.check_output(command, stderr=subprocess.STDOUT).strip().splitlines()
    result = b"\n".join(lines).decode("utf-8")

    if strip_ansi:
        result = ansi_clean(result)

    return result


def gdb_run_silent_cmd(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY, strip_ansi=STRIP_ANSI_DEFAULT):
    """Disable the output and run entirely the `target` binary."""
    if not before:
        before = []

    before += ["gef config context.clear_screen False",
               "gef config context.layout '-code -stack'",
               "run"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_run_cmd_last_line(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY, strip_ansi=STRIP_ANSI_DEFAULT):
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_start_silent_cmd(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY, strip_ansi=STRIP_ANSI_DEFAULT):
    """Execute a command in GDB by starting an execution context. This command disables the `context`
    and sets a tbreak at the most convenient entry point."""
    if not before:
        before = []

    before += ["gef config context.clear_screen False",
               "gef config context.layout '-code -stack'",
               "entry-break"]
    return gdb_run_cmd(cmd, before, after, target, strip_ansi)


def gdb_start_silent_cmd_last_line(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY, strip_ansi=STRIP_ANSI_DEFAULT):
    """Execute `gdb_start_silent_cmd()` and return only the last line of its output."""
    return gdb_start_silent_cmd(cmd, before, after, target, strip_ansi).splitlines()[-1]


def gdb_test_python_method(meth, before="", after="", target=PATH_TO_DEFAULT_BINARY, strip_ansi=STRIP_ANSI_DEFAULT):
    cmd = "pi {}print({});{}".format(before+";" if before else "", meth, after)
    return gdb_start_silent_cmd(cmd, target=target, strip_ansi=strip_ansi)
