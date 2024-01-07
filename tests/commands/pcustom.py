"""
pcustom command test module
"""

import tempfile
import pathlib

from tests.base import RemoteGefUnitTestGeneric

from tests.utils import (
    is_64b,
    debug_target,
    GEF_DEFAULT_TEMPDIR,
)


struct = b"""from ctypes import *
class foo_t(Structure):
    _fields_ = [("a", c_int32),("b", c_int32),]
class goo_t(Structure):
    _fields_ = [("a", c_int32), ("b", c_int32), ("c", POINTER(foo_t)), ("d", c_int32), ("e", c_int32),]
"""


class PcustomCommand(RemoteGefUnitTestGeneric):
    """`pcustom` command test module"""

    def setUp(self) -> None:
        self._target=debug_target("pcustom")
        return super().setUp()

    def test_cmd_pcustom(self):
        gdb = self._gdb
        with tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR) as dd:
            dirpath = pathlib.Path(dd).absolute()

            with tempfile.NamedTemporaryFile(dir = dirpath, suffix=".py") as fd:
                fd.write(struct)
                fd.seek(0)
                fd.flush()

                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                gdb.execute("run")
                res = gdb.execute("gef config pcustom.struct_path", to_string=True)
                self.assertIn(f"pcustom.struct_path (str) = \"{dirpath}\"", res)

                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                res = gdb.execute("pcustom", to_string=True)
                structline = [x for x in res.splitlines() if x.startswith(f" →  {dirpath}", to_string=True) ][0]
                self.assertIn("goo_t", structline)
                self.assertIn("foo_t", structline)

                # bad structure name with address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                gdb.execute("run")
                res = gdb.execute("pcustom meh_t 0x1337100", to_string=True)
                self.assertIn("Session is not active", res)



    def test_cmd_pcustom_show(self):
        gdb = self._gdb
        with tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR) as dd:
            dirpath = pathlib.Path(dd).absolute()

            with tempfile.NamedTemporaryFile(dir = dirpath, suffix=".py") as fd:
                fd.write(struct)
                fd.seek(0)
                fd.flush()

                # no address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                gdb.execute("run")
                res = gdb.execute("pcustom foo_t", to_string=True)
                if is_64b():
                    self.assertIn("0000   a                     c_int  /* size=0x4 */", res)
                    self.assertIn("0004   b                     c_int  /* size=0x4 */", res)
                else:
                    self.assertIn("0000   a                     c_long  /* size=0x4 */", res)
                    self.assertIn("0004   b                     c_long  /* size=0x4 */", res)

                # with address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                gdb.execute("run")
                res = gdb.execute("pcustom goo_t 0x1337100", to_string=True)
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
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                res = gdb.execute("pcustom meh_t", to_string=True)
                self.assertIn("No structure named 'meh_t' found", res)

                # bad structure name with address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                res = gdb.execute("pcustom meh_t 0x1337100", to_string=True)
                self.assertIn("No structure named 'meh_t' found", res)
