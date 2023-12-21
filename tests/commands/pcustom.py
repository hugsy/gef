"""
pcustom command test module
"""

import tempfile
import pathlib

from tests.utils import (
    gdb_run_cmd,
    gdb_run_silent_cmd,
    is_64b,
    debug_target,
    GEF_DEFAULT_TEMPDIR,
    GefUnitTestGeneric,
)


struct = b"""from ctypes import *
class foo_t(Structure):
    _fields_ = [("a", c_int32),("b", c_int32),]
class goo_t(Structure):
    _fields_ = [("a", c_int32), ("b", c_int32), ("c", POINTER(foo_t)), ("d", c_int32), ("e", c_int32),]
"""


class PcustomCommand(GefUnitTestGeneric):
    """`pcustom` command test module"""

    def test_cmd_pcustom(self):
        with tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR) as dd:
            dirpath = pathlib.Path(dd).absolute()

            with tempfile.NamedTemporaryFile(dir = dirpath, suffix=".py") as fd:
                fd.write(struct)
                fd.seek(0)
                fd.flush()

                res = gdb_run_cmd("gef config pcustom.struct_path",
                                before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                self.assertIn(f"pcustom.struct_path (str) = \"{dirpath}\"", res)

                res = gdb_run_cmd("pcustom", before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                structline = [x for x in res.splitlines() if x.startswith(f" →  {dirpath}") ][0]
                self.assertIn("goo_t", structline)
                self.assertIn("foo_t", structline)

                # bad structure name with address
                res = gdb_run_cmd("pcustom meh_t 0x1337100",
                                    before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                self.assertIn("Session is not active", res)



    def test_cmd_pcustom_show(self):
        with tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR) as dd:
            dirpath = pathlib.Path(dd).absolute()

            with tempfile.NamedTemporaryFile(dir = dirpath, suffix=".py") as fd:
                fd.write(struct)
                fd.seek(0)
                fd.flush()

                # no address
                res = gdb_run_cmd("pcustom foo_t",
                                before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                if is_64b():
                    self.assertIn("0000   a                     c_int  /* size=0x4 */", res)
                    self.assertIn("0004   b                     c_int  /* size=0x4 */", res)
                else:
                    self.assertIn("0000   a                     c_long  /* size=0x4 */", res)
                    self.assertIn("0004   b                     c_long  /* size=0x4 */", res)

                # with address
                res = gdb_run_silent_cmd("pcustom goo_t 0x1337100", target=debug_target("pcustom"),
                                        before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                if is_64b():
                    self.assertIn(f"""0x1337100+0x00 a :                      3 (c_int)
0x1337100+0x04 b :                      4 (c_int)
0x1337100+0x08 c :                      """, res)
                    self.assertIn(f"""  0x1337000+0x00 a :                      1 (c_int)
  0x1337000+0x04 b :                      2 (c_int)
0x1337100+0x10 d :                      12 (c_int)
0x1337100+0x14 e :                      13 (c_int)""", res)
                else:
                    self.assertIn(f"""0x1337100+0x00 a :                      3 (c_long)
0x1337100+0x04 b :                      4 (c_long)
0x1337100+0x08 c :                      """, res)
                    self.assertIn(f"""  0x1337000+0x00 a :                      1 (c_long)
  0x1337000+0x04 b :                      2 (c_long)
0x1337100+0x0c d :                      12 (c_long)
0x1337100+0x10 e :                      13 (c_long)""", res)

                # bad structure name
                res = gdb_run_cmd("pcustom meh_t",
                                    before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                self.assertIn("No structure named 'meh_t' found", res)

                # bad structure name with address
                res = gdb_run_silent_cmd("pcustom meh_t 0x1337100", target=debug_target("pcustom"),
                                        before=[f"gef config pcustom.struct_path {dirpath}",])
                self.assertNoException(res)
                self.assertIn("No structure named 'meh_t' found", res)
