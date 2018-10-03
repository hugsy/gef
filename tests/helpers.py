import subprocess

PATH_TO_DEFAULT_BINARY = "./tests/binaries/default.out"


def gdb_run_cmd(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY):
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = [
        "gdb", "-q", "-nx",
        "-ex", "source /tmp/gef.py",
        "-ex", "gef config gef.disable_color True",
        "-ex", "gef config gef.debug True"
    ]

    if before:
        for _ in before: command += ["-ex", _]

    command += ["-ex", cmd]

    if after:
        for _ in after: command += ["-ex", _]

    command += ["-ex", "quit", "--", target]

    lines = subprocess.check_output(command, stderr=subprocess.STDOUT).strip().splitlines()
    return b"\n".join(lines)


def gdb_run_silent_cmd(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY):
    """Disable the output and run entirely the `target` binary."""
    if not before:
        before = []

    before += ["gef config context.clear_screen False",
               "gef config context.layout '-code -stack'",
               "run"]
    return gdb_run_cmd(cmd, before, after, target)


def gdb_run_cmd_last_line(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY):
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_cmd(cmd, before, after, target).splitlines()[-1]


def gdb_start_silent_cmd(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY):
    """Execute a command in GDB by starting an execution context. This command disables the `context`
    and set a tbreak at the most convenient entry point."""
    if not before:
        before = []

    before += ["gef config context.clear_screen False",
               "gef config context.layout '-code -stack'",
               "entry-break"]
    return gdb_run_cmd(cmd, before, after, target)


def gdb_start_silent_cmd_last_line(cmd, before=None, after=None, target=PATH_TO_DEFAULT_BINARY):
    """Execute `gdb_start_silent_cmd()` and return only the last line of its output."""
    return gdb_start_silent_cmd(cmd, before, after, target).splitlines()[-1]


def gdb_test_python_method(meth, before="", after="", target=PATH_TO_DEFAULT_BINARY):
    cmd = "pi {}print({});{}".format(before+";" if before else "", meth, after)
    return gdb_start_silent_cmd(cmd, target=target)
