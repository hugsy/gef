"""
keystone-assemble command test module
"""


from tests.utils import GefUnitTestGeneric, gdb_run_silent_cmd, gdb_start_silent_cmd


class KeystoneAssembleCommand(GefUnitTestGeneric):
    """`keystone-assemble` command test module"""


    def test_cmd_keystone_assemble(self):
        self.assertNotIn("keystone", gdb_run_silent_cmd("gef missing"))
        cmds = [
            "assemble --arch arm   --mode arm                  add  r0, r1, r2",
            "assemble --arch arm   --mode arm     --endian big add  r0, r1, r2",
            "assemble --arch arm   --mode thumb                add  r0, r1, r2",
            "assemble --arch arm   --mode thumb   --endian big add  r0, r1, r2",
            "assemble --arch arm   --mode armv8                add  r0, r1, r2",
            "assemble --arch arm   --mode armv8   --endian big add  r0, r1, r2",
            "assemble --arch arm   --mode thumbv8              add  r0, r1, r2",
            "assemble --arch arm   --mode thumbv8 --endian big add  r0, r1, r2",
            "assemble --arch arm64 --mode 0                    add x29, sp, 0; mov  w0, 0; ret",
            "assemble --arch mips  --mode mips32               add $v0, 1",
            "assemble --arch mips  --mode mips32  --endian big add $v0, 1",
            "assemble --arch mips  --mode mips64               add $v0, 1",
            "assemble --arch mips  --mode mips64  --endian big add $v0, 1",
            "assemble --arch ppc   --mode ppc32   --endian big ori 0, 0, 0",
            "assemble --arch ppc   --mode ppc64                ori 0, 0, 0",
            "assemble --arch ppc   --mode ppc64   --endian big ori 0, 0, 0",
            "assemble --arch sparc --mode sparc32              set 0, %o0",
            "assemble --arch sparc --mode sparc32 --endian big set 0, %o0",
            "assemble --arch sparc --mode sparc64 --endian big set 0, %o0",
            "assemble --arch x86   --mode 16                   mov ax,  0x42",
            "assemble --arch x86   --mode 32                   mov eax, 0x42",
            "assemble --arch x86   --mode 64                   mov rax, 0x42",
        ]
        for cmd in cmds:
            res = gdb_start_silent_cmd(cmd)
            self.assertNoException(res)
            self.assertTrue(len(res.splitlines()) > 1)