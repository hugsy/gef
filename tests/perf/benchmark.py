"""
Simple benchmarking for pytest
"""

import pytest

from ..base import RemoteGefUnitTestGeneric


class BenchmarkBasicApi(RemoteGefUnitTestGeneric):
    @pytest.fixture(autouse=True)
    def benchmark(self, benchmark):
        self.__benchmark = benchmark

    @pytest.mark.benchmark(warmup=True)
    def test_cmd_context(self):
        gdb = self._gdb
        gdb.execute("start")
        self.__benchmark(gdb.execute, "context")

    @pytest.mark.benchmark(warmup=True)
    def test_cmd_context_regs(self):
        gdb = self._gdb
        gdb.execute("start")
        self.__benchmark(gdb.execute, "context regs")

    @pytest.mark.benchmark(warmup=True)
    def test_cmd_context_stack(self):
        gdb = self._gdb
        gdb.execute("start")
        self.__benchmark(gdb.execute, "context stack")

    @pytest.mark.benchmark(warmup=True)
    def test_cmd_context_code(self):
        gdb = self._gdb
        gdb.execute("start")
        self.__benchmark(gdb.execute, "context code")

    @pytest.mark.benchmark
    def test_gef_memory_maps(self):
        gdb = self._gdb
        gdb.execute("start")
        gef = self._gef

        def vmmap():
            return gef.memory.maps

        self.__benchmark(vmmap)

    @pytest.mark.benchmark
    def test_elf_parsing(self):
        root = self._conn.root
        ElfCls = root.eval("Elf")
        assert ElfCls
        self.__benchmark(ElfCls, "/bin/ls")
