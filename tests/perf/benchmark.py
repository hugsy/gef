"""
Simple benchmarking for pytest
"""

import pytest

from ..base import RemoteGefUnitTestGeneric


class BenchmarkBasicApi(RemoteGefUnitTestGeneric):
    @pytest.fixture(autouse=True)
    def benchmark(self, benchmark):
        self.__benchmark = benchmark

    @pytest.mark.benchmark
    def test_cmd_context(self):
        gdb = self._gdb
        gdb.execute("start")
        self.__benchmark(gdb.execute, "context")

    @pytest.mark.benchmark
    def test_gef_memory_maps(self):
        gdb = self._gdb
        gdb.execute("start")
        gef = self._gef
        assert self.__benchmark

        def vmmap():
            return gef.memory.maps

        self.__benchmark(vmmap)

    @pytest.mark.benchmark
    def test_elf_parsing(self):
        root = self._conn.root
        ElfCls = root.eval("Elf")
        assert ElfCls
        assert self.__benchmark
        self.__benchmark(ElfCls, "/bin/ls")
