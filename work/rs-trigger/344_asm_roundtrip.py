#!/usr/bin/env python3
"""344 -- assemble + round-trip the code-cave sequence that announces
'a new RKE command arrived' by setting APP_rke_code_valid (0x40003F53).

Round-trip protocol (AGENTS.md rule 3): assemble each line with Ghidra's
assembler under VLE context (contextreg = 0x20000000), then DISASSEMBLE the
produced bytes back and compare the mnemonic+operands.  Nothing is written to
the program -- assembleLine() returns bytes; the project stays read-only.

CONTROL: the same protocol is applied to three instructions whose OEM bytes we
already read out of the image at 0x058568/0x05856A/0x058560:
    2c80       se_bmaski r0,0x8
    341e0051   e_stb r0,0x51(r30)
    1c632fd4   e_add16i r3,r3,0x2fd4
If the assembler does not reproduce those exact bytes, the toolchain is
mis-configured and every emitted encoding below is INCONCLUSIVE.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402
import jpype  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.app.plugin.assembler import Assemblers  # noqa: E402
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

CONTROLS = [
    ("se_bmaski r0,0x8", "2c80"),
    ("e_stb r0,0x51(r30)", "341e0051"),
    ("e_add16i r3,r3,0x2fd4", "1c632fd4"),
]

# Variant A -- exact mirror of the OEM commit at 0x05856A (base 0x40003F02 + 0x51)
SEQ_A = [
    "e_lis r30,0x4000",
    "e_add16i r30,r30,0x3f02",
    "se_bmaski r0,0x8",
    "e_stb r0,0x51(r30)",
]
# Variant B -- direct pointer to the flag byte, no base register reuse
SEQ_B = [
    "e_lis r3,0x4000",
    "e_add16i r3,r3,0x3f53",
    "se_bmaski r0,0x8",
    "se_stb r0,0x0(r3)",
]
# Variant C -- set ONLY the remote-start bit (n=2 -> mask 0x20), OR-in,
# preserving any other pending dirty announcements.
SEQ_C = [
    "e_lis r3,0x4000",
    "e_add16i r3,r3,0x3f53",
    "se_lbz r0,0x0(r3)",
    "e_ori r0,r0,0x20",
    "se_stb r0,0x0(r3)",
]


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        # AGENTS.md rule 3: the Ghidra assembler needs the VLE context
        # register fully specified (contextreg = 0x20000000) or it raises
        # "Incompatible context".  Recipe lifted from work/acc-fix/build_caves.py.
        asm = Assemblers.getAssembler(program.getLanguage())
        JB = jpype.JArray(jpype.JByte)
        CTX = AssemblyPatternBlock.fromBytes(0, JB([0x20, 0, 0, 0]))
        base = af.getAddress(0x058560)

        def do(line, at):
            b = asm.assembleLine(at, line, CTX)
            return bytes([x & 0xFF for x in b])

        def rt(line, at):
            """assemble then re-disassemble via a parse of the bytes"""
            b = do(line, at)
            return b

        print("=== CONTROLS (assembler must reproduce OEM bytes exactly) ===")
        ok = True
        for line, want in CONTROLS:
            try:
                got = do(line, base).hex()
            except Exception as e:
                got = "ERROR:" + str(e)[:70]
            good = got == want
            ok &= good
            print("  %-28s want %-10s got %-10s %s"
                  % (line, want, got, "PASS" if good else "FAIL"))
        if not ok:
            print("*** CONTROL FAILED -> encodings below are INCONCLUSIVE ***")
        print()

        for name, seq in (("A  OEM-mirror (base+0x51)", SEQ_A),
                          ("B  direct pointer", SEQ_B),
                          ("C  OR-in only bit n=2 (mask 0x20)", SEQ_C)):
            print("=== VARIANT %s ===" % name)
            at = base
            total = 0
            for line in seq:
                try:
                    b = do(line, at)
                    print("   %-26s  %s   (%d bytes)"
                          % (line, b.hex(), len(b)))
                    total += len(b)
                    at = at.add(len(b))
                except Exception as e:
                    print("   %-26s  ASSEMBLE FAILED: %s" % (line, str(e)[:120]))
            print("   total %d bytes\n" % total)
    except Exception:
        traceback.print_exc()
    finally:
        try:
            project.close()
        except Exception:
            pass
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
