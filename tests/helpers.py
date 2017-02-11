import subprocess

def gdb_run_command(cmd, before=[], after=[]):
    """Execute a command inside GDB. `before` and `after` are lists of commands to be executed
    before (resp. after) the command to test."""
    command = ["gdb", "-q", "-nx", "-ex", "source /tmp/gef.py", "-ex", "gef config gef.debug True"]

    if len(before):
        for _ in before: command+= ["-ex", _]

    command += ["-ex", cmd]

    if len(after):
        for _ in after: command+= ["-ex", _]

    command+= ["-ex", "quit", "--", "/bin/ls"]
    lines = subprocess.check_output(command, stderr=subprocess.STDOUT).strip().splitlines()
    return "\n".join(lines)


def gdb_run_command_last_line(cmd, before=[], after=[]):
    """Execute a command in GDB, and return only the last line of its output."""
    return gdb_run_command(cmd, before, after).splitlines()[-1]


def gdb_start_silent_command(cmd, before=[], after=[]):
    """Execute a command in GDB by starting an execution context. This command disables the `context`
    and set a tbreak at the most convenient entry point."""
    before += ["gef config context.clear_screen False",
               "gef config context.layout ''",
               "entry-break"]
    return gdb_run_command(cmd, before, after)


def gdb_start_silent_command_last_line(cmd, before=[], after=[]):
    """Execute `gdb_start_silent_command()` and return only the last line of its output."""
    before += ["gef config context.clear_screen False",
               "gef config context.layout ''",
               "entry-break"]
    return gdb_start_silent_command(cmd, before, after).splitlines()[-1]


def gdb_test_python_method(meth, before="", after=""):
    cmd = "pi {}print({});{}".format(before+";" if len(before)>0 else "", meth, after)
    return gdb_start_silent_command(cmd)
