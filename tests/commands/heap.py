"""
Heap commands test module
"""

import pytest

from tests.base import RemoteGefUnitTestGeneric
from tests.utils import (
    ARCH,
    ERROR_INACTIVE_SESSION_MESSAGE,
    debug_target,
    findlines,
    is_32b,
    is_64b,
)


class HeapCommand(RemoteGefUnitTestGeneric):
    """Generic class for command testing, that defines all helpers"""

    def setUp(self) -> None:
        self._target = debug_target("heap")
        return super().setUp()

    def test_cmd_heap_arenas(self):
        gdb = self._gdb
        cmd = "heap arenas"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("start")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Arena(base=", res)

    def test_cmd_heap_set_arena(self):
        gdb = self._gdb
        cmd = "heap set-arena &main_arena"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        gdb.execute(cmd)
        res = gdb.execute("heap arenas", to_string=True)
        self.assertIn("Arena(base=", res)

    def test_cmd_heap_chunk_no_arg(self):
        gdb = self._gdb
        cmd = "heap chunk p1"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA", res)

    def test_cmd_heap_chunk_with_number(self):
        gdb = self._gdb
        cmd = "heap chunk --number 2 p1"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res: str = gdb.execute(cmd, to_string=True)
        chunklines = findlines("Chunk(addr=", res)
        self.assertEqual(len(chunklines), 2)

    def test_cmd_heap_chunks(self):
        gdb = self._gdb
        cmd = "heap chunks"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)

    def test_cmd_heap_chunks_summary(self):
        gdb = self._gdb
        cmd = "heap chunks --summary"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("== Chunk distribution by size", res)
        self.assertIn("== Chunk distribution by flag", res)

    def test_cmd_heap_chunks_min_size_filter(self):
        gdb = self._gdb
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute("heap chunks", to_string=True)
        )

        gdb.execute("run")

        cmd = "heap chunks --min-size 16"
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Chunk(addr=", res)

        cmd = "heap chunks --min-size 1048576"
        res = gdb.execute(cmd, to_string=True)
        self.assertNotIn("Chunk(addr=", res)

    def test_cmd_heap_chunks_max_size_filter(self):
        gdb = self._gdb
        cmd = "heap chunks --max-size 160"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")

        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Chunk(addr=", res)

        cmd = "heap chunks --max-size 16"

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertNotIn("Chunk(addr=", res)

    def test_cmd_heap_chunks_with_count(self):
        gdb = self._gdb
        cmd = "heap chunks --count 1"
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Chunk(addr=", res)

        cmd = "heap chunks --count 0"

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertNotIn("Chunk(addr=", res)


class HeapCommandNonMain(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("heap-non-main")
        return super().setUp()

    def test_cmd_heap_chunks(self):
        gdb = self._gdb
        cmd = "heap chunks"

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)
        chunks = [line for line in res.splitlines() if "Chunk(addr=" in line]

        cmd = "python gdb.execute(f'heap chunks {int(list(gef.heap.arenas)[1]):#x}')"

        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertNotIn("using '&main_arena' instead", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)
        non_main_chunks = [line for line in res.splitlines() if "Chunk(addr=" in line]
        # make sure that the chunks of each arena are distinct
        self.assertNotEqual(chunks, non_main_chunks)

    def test_cmd_heap_bins_non_main(self):
        gdb = self._gdb
        gef = self._gef
        gdb.execute("set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0")
        gdb.execute("run")

        next_arena: int = gef.heap.main_arena.next
        cmd = f"python gdb.execute(f'heap bins fast {next_arena:#x}')"
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("size=0x20", res)

    @pytest.mark.tcache
    def test_cmd_heap_bins_tcache(self):
        gdb = self._gdb
        gdb.execute("run")

        cmd = "heap bins tcache"
        res = gdb.execute(cmd, to_string=True)
        tcachelines = findlines("Tcachebins[idx=", res)
        self.assertEqual(len(tcachelines), 1)
        if ARCH in ("i686",):
            self.assertIn("Tcachebins[idx=1, size=0x20, count=1]", tcachelines[0])
        elif is_32b():
            self.assertIn("Tcachebins[idx=2, size=0x20, count=1]", tcachelines[0])
        else:
            self.assertIn("Tcachebins[idx=0, size=0x20, count=1]", tcachelines[0])


class HeapCommandMultipleHeaps(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("heap-multiple-heaps")
        return super().setUp()

    def test_cmd_heap_chunks_mult_heaps(self):
        gdb = self._gdb

        gdb.execute("run")
        py_cmd = 'gdb.execute(f"heap set-arena {int(list(gef.heap.arenas)[1]):#x}")'

        gdb.execute(f"python {py_cmd}")
        cmd = "heap chunks"
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)


class HeapCommandClass(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("class")
        return super().setUp()

    def test_cmd_heap_chunks_summary_with_type_resolved(self):
        gdb = self._gdb
        cmd = "heap chunks --summary --resolve"
        gdb.execute("b B<TraitA, TraitB>::Run()")
        gdb.execute("run")
        lines = gdb.execute(cmd, to_string=True).splitlines()
        assert len(lines) > 0
        self.assertEqual("== Chunk distribution by size ==", lines[0])
        self.assertIn("== Chunk distribution by flag ==", lines)
        assert any( map(lambda x: "B<TraitA, TraitB>" in x, lines))


class HeapCommandFastBins(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("heap-fastbins")
        return super().setUp()

    def test_cmd_heap_bins_fast(self):
        gdb = self._gdb
        cmd = "heap bins fast"
        gdb.execute("set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0")
        self.assertEqual(
            ERROR_INACTIVE_SESSION_MESSAGE, gdb.execute(cmd, to_string=True)
        )
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        # ensure fastbins is populated
        self.assertIn("Fastbins[idx=0, size=", res)
        self.assertIn("Chunk(addr=", res)


class HeapCommandBins(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("heap-bins")
        self.expected_large_bin_size = 0x420 if ARCH == "i686" or is_64b() else 0x418
        self.expected_small_bin_size = 0x20 if ARCH == "i686" or is_64b() else 0x18
        self.expected_unsorted_bin_size = 0x430 if ARCH == "i686" or is_64b() else 0x428
        return super().setUp()

    def test_cmd_heap_bins_large(self):
        gdb = self._gdb
        gdb.execute("run")
        cmd = "heap bins large"
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Found 1 chunks in 1 large non-empty bins", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn(f"size={self.expected_large_bin_size:#x}", res)

    def test_cmd_heap_bins_small(self):
        gdb = self._gdb
        cmd = "heap bins small"
        gdb.execute("set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0")
        gdb.execute("run")
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Found 1 chunks in 1 small non-empty bins", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn(f"size={self.expected_small_bin_size:#x}", res)

    def test_cmd_heap_bins_unsorted(self):
        gdb = self._gdb
        gdb.execute("run")
        cmd = "heap bins unsorted"
        res = gdb.execute(cmd, to_string=True)
        self.assertIn("Found 1 chunks in unsorted bin", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn(f"size={self.expected_unsorted_bin_size:#x}", res)


class HeapCommandTcache(RemoteGefUnitTestGeneric):
    def setUp(self) -> None:
        self._target = debug_target("heap-tcache")
        self.expected_tcache_bin_size = 0x20 if ARCH == "i686" or is_64b() else 0x18
        return super().setUp()

    @pytest.mark.tcache
    def test_cmd_heap_bins_tcache_all(self):
        gdb = self._gdb
        gdb.execute("run")

        cmd = "heap bins tcache all"
        res = gdb.execute(cmd, to_string=True)
        # ensure there's 2 tcachebins
        tcachelines = findlines("Tcachebins[idx=", res)
        self.assertEqual(len(tcachelines), 2)
        if ARCH in ("i686",):
            self.assertIn("Tcachebins[idx=1, size=0x20, count=3]", tcachelines[0])
            self.assertIn("Tcachebins[idx=2, size=0x30, count=3]", tcachelines[1])
        elif is_32b():
            self.assertIn("Tcachebins[idx=1, size=0x18, count=3]", tcachelines[0])
            self.assertIn("Tcachebins[idx=4, size=0x30, count=3]", tcachelines[1])
        else:
            self.assertIn("Tcachebins[idx=0, size=0x20, count=3]", tcachelines[0])
            self.assertIn("Tcachebins[idx=1, size=0x30, count=3]", tcachelines[1])
