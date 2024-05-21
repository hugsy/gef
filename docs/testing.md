## Testing GEF

This page describes how GEF testing is done. Any new command/functionality must receive adequate
testing to be merged. Also PR failing CI (test + linting) won't be merged either.

### Prerequisites

All the prerequisite packages are in `requirements.txt` file at the root of the project. So running

```bash
python -m pip install -r tests/requirements.txt --user -U
```

is enough to get started.

### Running tests

#### Basic `pytest`

For testing GEF on the architecture on the host running the tests (most cases), simply run

```bash
cd /root/of/gef
python3 -m pytest -v -k "not benchmark" tests
```

Note that to ensure compatibility, tests must be executed with the same Python version GDB was
compiled against. To obtain this version, you can execute the following command:

```bash
gdb -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit
```

At the end, a summary of explanation will be shown, clearly indicating the tests that have failed,
for instance:

```text
=================================== short test summary info ==================================
FAILED tests/commands/heap.py::HeapCommand::test_cmd_heap_bins_large - AssertionError: 'siz...
FAILED tests/commands/heap.py::HeapCommand::test_cmd_heap_bins_small - AssertionError: 'siz...
FAILED tests/commands/heap.py::HeapCommand::test_cmd_heap_bins_unsorted - AssertionError: '...
======================== 3 failed, 4 passed, 113 deselected in 385.77s (0:06:25)==============
```

You can then use `pytest` directly to help you fix each error specifically.

#### Using `pytest`

GEF entirely relies on [`pytest`](https://pytest.org) for its testing. Refer to the project
documentation for details.

Adding new code __requires__ extensive testing. Tests can be added in their own module in the
`tests/` folder. For example, if adding a new command to `gef`, a new test module should be created
and located in `/root/of/gef/tests/commands/my_new_command.py`. The test class __must__ inherit
`tests.base.RemoteGefUnitTestGeneric`. This class allows one to manipulate gdb and gef through rpyc
under their respective `self._gdb` and `self._gef` attributes.

A skeleton of a test module would look something like:

```python
"""
`my-command` command test module
"""


from tests.utils import RemoteGefUnitTestGeneric


class MyCommandCommand(RemoteGefUnitTestGeneric):
    """`my-command` command test module"""

    def setUp(self) -> None:
        # By default, tests will be executed against the default.out binary
        # You can change this behavior in the `setUp` function
        self._target = debug_target("my-custom-binary-for-tests")
        return super().setUp()

    def test_cmd_my_command(self):
        # some convenience variables
        root, gdb, gef = self._conn.root, self._gdb, self._gef

        # You can then interact with any command from gdb or any class/function/variable from gef
        # For instance:

        # * tests that  `my-command` is expected to fail if the session is not active
        output = gdb.execute("my-command", to_string=True)
        assert output == ERROR_INACTIVE_SESSION_MESSAGE

        # * `my-command` must print "Hello World" message when executed in running context
        gdb.execute("start")
        output = gdb.execute("my-command", to_string=True)
        assert "Hello World" == output
```

You might want to refer to the following documentations:

*  [`pytest`](https://docs.pytest.org/en/)
*  [`gdb Python API`](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Python-API.html)
*  (maybe) [`rpyc`](https://rpyc.readthedocs.io/en/latest/)

When running your test, you can summon `pytest` with the `--pdb` flag to enter the python testing
environment to help you get more information about the reason of failure.

One of the most convenient ways to test `gef` properly is using the `pytest` integration of modern
editors such as VisualStudio Code or PyCharm. Without proper tests, new code will not be integrated.

Also note that GEF can be remotely controlled using the script `scripts/remote_debug.py` as such:

```text
$ gdb -q -nx
(gdb) source /path/to/gef/gef.py
[...]
gef➤  source /path/to/gef/scripts/remote_debug.py
gef➤  pi start_rpyc_service(4444)
```

Here RPyC will be started on the local host, and bound to the TCP port 4444. We can now connect
using a regular Python REPL:

```text
>>> import rpyc
>>> c = rpyc.connect("localhost", 4444)
>>> gdb = c.root.gdb
>>> gef = c.root.gef
# We can now fully control the remote GDB
>>> gdb.execute("file /bin/ls")
>>> gdb.execute("start")
>>> print(hex(gef.arch.pc))
0x55555555aab0
>>> print(hex(gef.arch.sp))
0x7fffffffdcf0
```

### Linting GEF

You can use the Makefile at the root of the project to get the proper linting settings. For most
cases, the following command is enough:

```bash
cd /root/of/gef
python3 -m pylint --rcfile .pylintrc
```

Note that to ensure compatibility, tests must be executed with the same Python version GDB was
compiled against. To obtain this version, you can execute the following command:

```bash
gdb -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit
```

### Code quality

To ensure a consistent code quality and make it easy for both contributors and developers, GEF and
GEF-Extras both rely on [`pre-commit`](https://pre-commit.com). The `pre-commit` tool is a
framework used to manage and maintain multi-language pre-commit hooks. These hooks are scripts that
run automatically before each commit to identify issues in code, such as missing semicolons,
trailing whitespace, and debug statements. This helps in ensuring code quality and consistency
before submission to code review, and therefore is triggered automatically when submitting a Pull
Request to GEF. This check is treated equally with the unit tests and therefore failing to pass
will result in your PR not being merged.

`pre-commit` is part of the [dev package requirements](https://github.com/hugsy/gef/blob/main/tests/requirements.txt)

```console
cd /root/to/gef/repo
python -m pip install --user -r tests/requirements.txt
```

But if you need to install separately it can be done using

```console
python -m pip install pre-commit
```

And to enable it

```console
pre-commit install
```

By default, `pre-commit` will use git hook to run the validation checks after each commit but you
can modify this behavior as desired or even run it manually

```console
pre-commit run --all-files
```

By default, `pre-commit` will report and attempt to fix the code to match what the coding style
defined with GEF.


### Benchmarking GEF

Benchmarking relies on `pytest-benchmark` and is experimental for now.

You can run all benchmark test cases as such:

```bash
cd /root/of/gef
pytest -k benchmark
```

which will return (after some time) an execution summary

```text
tests/perf/benchmark.py ..                                                               [100%]


---------------------------------------- benchmark: 3 tests -----------------------------------
Name (time in ms)          Min                 Max                Mean            StdDev              Median                IQR            Outliers     OPS            Rounds  Iterations
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
time_baseline         612.2325 (1.0)      630.3416 (1.01)     623.7984 (1.01)     7.2848 (1.64)     626.1485 (1.01)      9.9971 (1.81)          1;0  1.6031 (0.99)          5           1
time_cmd_context      613.8124 (1.00)     625.8964 (1.0)      620.1908 (1.0)      4.4532 (1.0)      619.8831 (1.0)       5.5109 (1.0)           2;0  1.6124 (1.0)           5           1
time_elf_parsing      616.5053 (1.01)     638.6965 (1.02)     628.1588 (1.01)     8.2465 (1.85)     629.0099 (1.01)     10.7885 (1.96)          2;0  1.5920 (0.99)          5           1
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Legend:
  Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
  OPS: Operations Per Second, computed as 1 / Mean
============================================== 3 passed, 117 deselected in 14.78s =============================================
```
