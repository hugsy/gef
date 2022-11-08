## Testing GEF

This page describes how GEF testing is done. Any new command/functionality must receive adequate testing to be merged. Also PR failing CI (test + linting) won't be merged either.


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

Note that to ensure compatibility, tests must be executed with the same Python version GDB was compiled against. To obtain this version, you can execute the following command:

```bash
gdb -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit
```

At the end, a summary of explanation will be shown, clearly indicating the tests that have failed, for instance:

```text
=================================== short test summary info ==================================
FAILED tests/commands/heap.py::HeapCommand::test_cmd_heap_bins_large - AssertionError: 'siz...
FAILED tests/commands/heap.py::HeapCommand::test_cmd_heap_bins_small - AssertionError: 'siz...
FAILED tests/commands/heap.py::HeapCommand::test_cmd_heap_bins_unsorted - AssertionError: '...
======================== 3 failed, 4 passed, 113 deselected in 385.77s (0:06:25)==============
```

You can then use `pytest` directly to help you fix each error specifically.


#### Using `pytest`

GEF entirely relies on [`pytest`](https://pytest.org) for its testing. Refer to the project documentation for details.

Adding a new command __requires__ for extensive testing in a new dedicated test module that should be located in `/root/of/gef/tests/commands/my_new_command.py`

A skeleton of a test module would look something like:

```python
"""
`my-command` command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_cmd, gdb_start_silent_cmd


class MyCommandCommand(GefUnitTestGeneric):
    """`my-command` command test module"""

    def test_cmd_my_command(self):
        # `my-command` is expected to fail if the session is not active
        self.assertFailIfInactiveSession(gdb_run_cmd("my-command"))

        # `my-command` should never throw an exception in GDB when running
        res = gdb_start_silent_cmd("my-command")
        self.assertNoException(res)

        # it also must print out a "Hello World" message
        self.assertIn("Hello World", res)
```

When running your test, you can summon `pytest` with the `--pdb` flag to enter the python testing environment to help you get more information about the reason of failure.

One of the most convenient ways to test `gef` properly is using the `pytest` integration of modern editors such as VisualStudio Code or PyCharm. Without proper tests, new code will not be integrated.


### Linting GEF

You can use the Makefile at the root of the project to get the proper linting settings. For most cases, the following command is enough:

```bash
cd /root/of/gef
python3 -m pylint --rcfile .pylintrc
```

Note that to ensure compatibility, tests must be executed with the same Python version GDB was compiled against. To obtain this version, you can execute the following command:

```bash
gdb -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit
```

### Benchmarking GEF

Benchmarking relies on `pytest-benchmark` and is experimental for now.

You can run all benchmark test cases as such:

```bash
cd /root/of/gef
pytest -k benchmark
```

which will return (after some time) an execution summary

```
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
