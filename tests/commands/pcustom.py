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
        self._target = debug_target("pcustom")
        return super().setUp()

    def test_cmd_pcustom(self):
        gdb = self._gdb
        with tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR) as dd:
            dirpath = pathlib.Path(dd).absolute()

            with tempfile.NamedTemporaryFile(dir=dirpath, suffix=".py") as fd:
                fd.write(struct)
                fd.seek(0)
                fd.flush()
                fpath = pathlib.Path(fd.name)

                #
                # Assign the struct_path setting
                #
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                res = gdb.execute("gef config pcustom.struct_path", to_string=True)
                self.assertIn(f'pcustom.struct_path (Path) = {dirpath}', res)

                #
                # List the structures in the files inside dirpath
                #
                lines = gdb.execute("pcustom list", to_string=True).splitlines()[1:]
                assert len(lines) == 1
                assert lines[0] == f" →  {fpath} (foo_t, goo_t)"

                #
                # Test with a bad structure name with address
                #
                gdb.execute("run")
                bad_struct_name = "meh_t"
                res = gdb.execute(f"pcustom {bad_struct_name} 0x1337100", to_string=True).strip()
                self.assertEqual(f"[!] No structure named '{bad_struct_name}' found", res)
                print(res)

    def test_cmd_pcustom_show(self):
        gdb = self._gdb
        with tempfile.TemporaryDirectory(prefix=GEF_DEFAULT_TEMPDIR) as dd:
            dirpath = pathlib.Path(dd).absolute()

            with tempfile.NamedTemporaryFile(dir=dirpath, suffix=".py") as fd:
                fd.write(struct)
                fd.seek(0)
                fd.flush()

                # no address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                gdb.execute("run")
                lines = gdb.execute("pcustom foo_t", to_string=True).splitlines()
                if is_64b():
                    self.assertEqual(
                        "0000   a                                  c_int             /* size=0x4 */",
                        lines[0],
                    )
                    self.assertEqual(
                        "0004   b                                  c_int             /* size=0x4 */",
                        lines[1],
                    )
                else:
                    self.assertEqual(
                        "0000   a                                  c_long             /* size=0x4 */",
                        lines[0],
                    )
                    self.assertEqual(
                        "0004   b                                  c_long             /* size=0x4 */",
                        lines[1],
                    )

                # with address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                gdb.execute("run")
                res = gdb.execute("pcustom goo_t 0x1337100", to_string=True)
                if is_64b():
                    self.assertIn(
                        f"""0x1337100+0x00 a :                      3 (c_int)
0x1337100+0x04 b :                      4 (c_int)
0x1337100+0x08 c :                      """,
                        res,
                    )
                    self.assertIn(
                        f"""  0x1337000+0x00 a :                      1 (c_int)
  0x1337000+0x04 b :                      2 (c_int)
0x1337100+0x10 d :                      12 (c_int)
0x1337100+0x14 e :                      13 (c_int)""",
                        res,
                    )
                else:
                    self.assertIn(
                        f"""0x1337100+0x00 a :                      3 (c_long)
0x1337100+0x04 b :                      4 (c_long)
0x1337100+0x08 c :                      """,
                        res,
                    )
                    self.assertIn(
                        f"""  0x1337000+0x00 a :                      1 (c_long)
  0x1337000+0x04 b :                      2 (c_long)
0x1337100+0x0c d :                      12 (c_long)
0x1337100+0x10 e :                      13 (c_long)""",
                        res,
                    )

                # bad structure name
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                res = gdb.execute("pcustom meh_t", to_string=True)
                self.assertIn("No structure named 'meh_t' found", res)

                # bad structure name with address
                gdb.execute(f"gef config pcustom.struct_path {dirpath}")
                res = gdb.execute("pcustom meh_t 0x1337100", to_string=True)
                self.assertIn("No structure named 'meh_t' found", res)
