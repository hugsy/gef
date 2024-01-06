"""
`gef.heap` test module.
"""

import pytest
import random

from tests.utils import ARCH, debug_target, is_64b
from tests.utils import RemoteGefUnitTestGeneric

TCACHE_BINS = 64

class GefHeapApi(RemoteGefUnitTestGeneric):
    """`gef.heap` test module."""

    def setUp(self) -> None:
        self._target = debug_target("heap")
        return super().setUp()

   # from https://elixir.bootlin.com/glibc/latest/source/malloc/malloc.c#L326
   # With rounding and alignment, the bins are...
   # idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   # idx 1   bytes 25..40 or 13..20
   # idx 2   bytes 41..56 or 21..28
   # etc.
    valid_sizes_32b = [16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120,
                      128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216,
                      224, 232, 240, 248, 256, 264, 272, 280, 288, 296, 304, 312, 320,
                      328, 336, 344, 352, 360, 368, 376, 384, 392, 400, 408, 416, 424,
                      432, 440, 448, 456, 464, 472, 480, 488, 496, 504, 512, 520, ]

    valid_sizes_64b = [32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
                  256, 272, 288, 304, 320, 336, 352, 368, 384, 400, 416, 432, 448,
                  464, 480, 496, 512, 528, 544, 560, 576, 592, 608, 624, 640, 656,
                  672, 688, 704, 720, 736, 752, 768, 784, 800, 816, 832, 848, 864,
                  880, 896, 912, 928, 944, 960, 976, 992, 1008, 1024, 1040]


    @property
    def valid_sizes(self):
        if ARCH == "i686" or is_64b():
            return self.valid_sizes_64b
        return self.valid_sizes_32b


    def test_func_gef_heap_tidx2size(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("run")
        for _ in range(5):
            idx = random.choice(range(TCACHE_BINS))
            size = gef.heap.tidx2size(idx)
            assert size in self.valid_sizes, f"idx={idx}"


    def test_func_gef_heap_csize2tidx(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("run")
        for _ in range(5):
            size = random.randint(0, 1032 if ARCH == "i686" or is_64b() else 516)
            idx = gef.heap.csize2tidx(size)
            assert idx in range(TCACHE_BINS), f"size={size}"


    @pytest.mark.skipif(ARCH not in ("x86_64",), reason=f"Skipped for {ARCH}")
    def test_func_gef_heap_malloc_align_address(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("run")
        values = (
            (0x08, 0x10),
            (0x11, 0x20),
            (0x23, 0x30),
            (0x13371337, 0x13371340),
        )

        for x, y in values:
            res = gef.heap.malloc_align_address(x)
            assert res == y


    def test_class_glibcarena_main_arena(self):
        gdb, gef = self._gdb, self._gef
        gdb.execute("run")
        addr1 = self._conn.root.eval("GlibcArena('main_arena').addr")
        addr2 = self._conn.root.eval("search_for_main_arena()")
        addr3 = gef.heap.main_arena
        assert addr1 == addr2
        assert addr2 == addr3
