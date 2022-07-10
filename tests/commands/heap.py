"""
Heap commands test module
"""

from tests.utils import (ARCH, GefUnitTestGeneric, _target, findlines,
                         gdb_run_cmd, gdb_run_silent_cmd, gdb_start_silent_cmd,
                         is_32b, is_64b)


class HeapCommand(GefUnitTestGeneric):
    """Generic class for command testing, that defines all helpers"""
    def setUp(self) -> None:
        # ensure those values reflects the allocations in the C source
        self.expected_tcache_bin_size = 0x20 if ARCH == "i686" or is_64b() else 0x18
        self.expected_small_bin_size = 0x20 if ARCH == "i686" or is_64b() else 0x18
        self.expected_large_bin_size = 0x420 if ARCH == "i686" or is_64b() else 0x418
        self.expected_unsorted_bin_size = 0x430 if ARCH == "i686" or is_64b() else 0x428
        return super().setUp()


    def test_cmd_heap_arenas(self):
        cmd = "heap arenas"
        target = _target("heap")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_start_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Arena(base=", res)


    def test_cmd_heap_set_arena(self):
        cmd = "heap set-arena &main_arena"
        target = _target("heap")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target, after=["heap arenas"])
        self.assertNoException(res)
        self.assertIn("Arena(base=", res)


    def test_cmd_heap_chunk_no_arg(self):
        cmd = "heap chunk p1"
        target = _target("heap")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA", res)


    def test_cmd_heap_chunk_with_number(self):
        target = _target("heap")
        cmd = "heap chunk --number 2 p1"
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        chunklines = findlines("Chunk(addr=", res)
        self.assertEqual(len(chunklines), 2)


    def test_cmd_heap_chunks(self):
        cmd = "heap chunks"
        target = _target("heap")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, target=target))
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)

        cmd = "python gdb.execute(f'heap chunks {int(list(gef.heap.arenas)[1]):#x}')"
        target = _target("heap-non-main")
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertNotIn("using '&main_arena' instead", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)


    def test_cmd_heap_chunks_mult_heaps(self):
        py_cmd = 'gdb.execute(f"heap set-arena {int(list(gef.heap.arenas)[1]):#x}")'
        before = ['run', 'python ' + py_cmd]
        cmd = "heap chunks"
        target = _target("heap-multiple-heaps")
        res = gdb_run_silent_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn("top chunk", res)


    def test_cmd_heap_bins_fast(self):
        cmd = "heap bins fast"
        before = ["set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0"]
        target = _target("heap-fastbins")
        self.assertFailIfInactiveSession(gdb_run_cmd(cmd, before=before, target=target))
        res = gdb_run_silent_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        # ensure fastbins is populated
        self.assertIn("Fastbins[idx=0, size=", res)
        self.assertIn("Chunk(addr=", res)


    def test_cmd_heap_bins_large(self):
        cmd = "heap bins large"
        target = _target("heap-bins")
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Found 1 chunks in 1 large non-empty bins", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn(f"size={self.expected_large_bin_size:#x}", res)


    def test_cmd_heap_bins_non_main(self):
        cmd = "python gdb.execute(f'heap bins fast {gef.heap.main_arena.addr:#x}')"
        before = ["set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0"]
        target = _target("heap-non-main")
        res = gdb_run_silent_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn("size=0x20", res)


    def test_cmd_heap_bins_small(self):
        cmd = "heap bins small"
        before = ["set environment GLIBC_TUNABLES glibc.malloc.tcache_count=0"]
        target = _target("heap-bins")
        res = gdb_run_silent_cmd(cmd, before=before, target=target)
        self.assertNoException(res)
        self.assertIn("Found 1 chunks in 1 small non-empty bins", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn(f"size={self.expected_small_bin_size:#x}", res)


    def test_cmd_heap_bins_tcache(self):
        cmd = "heap bins tcache"
        target = _target("heap-non-main")
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        tcachelines = findlines("Tcachebins[idx=", res)
        self.assertEqual(len(tcachelines), 1)
        if ARCH in ("i686",):
            self.assertIn("Tcachebins[idx=1, size=0x20, count=1]", tcachelines[0])
        elif is_32b():
            self.assertIn("Tcachebins[idx=2, size=0x20, count=1]", tcachelines[0])
        else:
            self.assertIn("Tcachebins[idx=0, size=0x20, count=1]", tcachelines[0])


    def test_cmd_heap_bins_tcache_all(self):
        cmd = "heap bins tcache all"
        target = _target("heap-tcache")
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
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

    def test_cmd_heap_bins_unsorted(self):
        cmd = "heap bins unsorted"
        target = _target("heap-bins")
        res = gdb_run_silent_cmd(cmd, target=target)
        self.assertNoException(res)
        self.assertIn("Found 1 chunks in unsorted bin", res)
        self.assertIn("Chunk(addr=", res)
        self.assertIn(f"size={self.expected_unsorted_bin_size:#x}", res)

