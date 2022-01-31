"""
`gef.heap` test module.
"""

import pytest
import random

from tests.utils import ARCH, gdb_test_python_method, is_64b
from tests.utils import GefUnitTestGeneric


def result_as_int(res: str) -> int:
    return int(gdb_test_python_method(res).splitlines()[-1])

TCACHE_BINS = 64

class GefHeapApi(GefUnitTestGeneric):
    """`gef.heap` test module."""

   # from https://elixir.bootlin.com/glibc/latest/source/malloc/malloc.c#L326
   # With rounding and alignment, the bins are...
   # idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   # idx 1   bytes 25..40 or 13..20
   # idx 2   bytes 41..56 or 21..28
   # etc.

    valid_sizes_32b = [16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224,
                       240, 256, 272, 288, 304, 320, 336, 352, 368, 384, 400, 416, 432,
                       448, 464, 480, 496, 512, 528, 544, 560, 576, 592, 608, 624, 640,
                       656, 672, 688, 704, 720, 736, 752, 768, 784, 800, 816, 832, 848,
                       864, 880, 896, 912, 928, 944, 960, 976, 992, 1008, 1024,]


    valid_sizes_64b = [32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
                  256, 272, 288, 304, 320, 336, 352, 368, 384, 400, 416, 432, 448,
                  464, 480, 496, 512, 528, 544, 560, 576, 592, 608, 624, 640, 656,
                  672, 688, 704, 720, 736, 752, 768, 784, 800, 816, 832, 848, 864,
                  880, 896, 912, 928, 944, 960, 976, 992, 1008, 1024, 1040]


    @property
    def valid_sizes(self):
        return self.valid_sizes_64b if is_64b() else self.valid_sizes_32b


    def test_func_gef_heap_tidx2size(self):
        for _ in range(10): # run 10 random tests
            idx = random.choice(range(TCACHE_BINS))
            size = result_as_int(f"gef.heap.tidx2size({idx})")
            self.assertIn(size, self.valid_sizes, f"idx={idx}")


    def test_func_gef_heap_csize2tidx(self):
        for _ in range(10):
            size = random.randint(0, 1024)
            idx = result_as_int(f"gef.heap.csize2tidx({size})")
            self.assertIn(idx, range(TCACHE_BINS), f"size={size}")


    @pytest.mark.skipif(ARCH not in ("x86_64",), reason=f"Skipped for {ARCH}")
    def test_func_gef_heap_malloc_align_address(self):
        values = (
            (0x08, 0x10),
            (0x11, 0x20),
            (0x23, 0x30),
            (0x13371337, 0x13371340),
        )
        for x, y in values:
            res = result_as_int(f"gef.heap.malloc_align_address({x})")
            self.assertEqual(res, y)

