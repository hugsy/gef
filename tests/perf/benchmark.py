"""
Simple benchmarking for pytest
"""

import pytest

from tests.utils import gdb_test_python_method, gdb_time_python_method, gdb_start_silent_cmd


def time_baseline(benchmark):
    benchmark(gdb_test_python_method, "")


def time_elf_parsing(benchmark):
    benchmark(gdb_test_python_method, "Elf('/bin/ls')")


def time_cmd_context(benchmark):
    benchmark(gdb_start_silent_cmd, "context")


def _time_elf_parsing_using_timeit():
    with pytest.raises(ValueError):
        res = gdb_time_python_method(
            "Elf('/bin/ls')",
            "from __main__ import Elf"
        )
        pytest.fail(f"execution_time={res}s")


def _time_cmd_context_using_timeit():
    with pytest.raises(ValueError):
        res = gdb_time_python_method(
            "gdb.execute('context')",
            "import gdb",
            before=("entry-break",),
            number=100
        )
        pytest.fail(f"execution_time={res}s")
