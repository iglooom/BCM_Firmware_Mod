#!/usr/bin/env python3
"""345 -- TRUE round trip: take the bytes 344 emitted, disassemble them back
under VLE context in a scratch region, and compare mnemonic+operands.
Also: callers of FUN_000AEEC6 (the RS-side test-and-clear consumer) and a
final check that 0x40003F53 has exactly ONE writer in the image.

The disassembly is done by writing into a temporary in-memory program? No --
the project is READ-ONLY.  Instead we use the Language's Disassembler directly
over a ByteMemBufferImpl, which touches nothing on disk.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402
import jpype  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.program.model.mem import ByteMemBufferImpl  # noqa: E402
from ghidra.program.model.lang import RegisterValue  # noqa: E402
from java.math import BigInteger  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

CASES = [
    ("e_lis r30,0x4000", "73c8e000"),
    ("e_add16i r30,r30,0x3f02", "1fde3f02"),
    ("se_bmaski r0,0x8", "2c80"),
    ("e_stb r0,0x51(r30)", "341e0051"),
    ("e_lis r3,0x4000", "7068e000"),
    ("e_add16i r3,r3,0x3f53", "1c633f53"),
    ("se_stb r0,0x0(r3)", "9003"),
    ("se_lbz r0,0x0(r3)", "8003"),
    ("e_ori r0,r0,0x20", "1800d020"),
    ("e_li r0,0xff", "7000e0ff"),
]


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        lang = program.getLanguage()
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()

        ctxreg = lang.getContextBaseRegister()
        ctxval = RegisterValue(ctxreg, BigInteger.valueOf(0x20000000))
        JB = jpype.JArray(jpype.JByte)

        print("=== ROUND TRIP: assembled bytes -> disassembly ===")
        allok = True
        for want_txt, hexb in CASES:
            raw = bytes.fromhex(hexb)
            buf = ByteMemBufferImpl(af.getAddress(0x058560),
                                    JB([b if b < 128 else b - 256 for b in raw]),
                                    True)
            try:
                pi = lang.parse(buf, ctxval, False)
                got = str(pi.getInstructionPrototype()
                          if False else pi).strip()
                # render mnemonic+operands
                got = "%s %s" % (pi.getMnemonic(buf),
                                 ",".join(str(pi.getDefaultOperandRepresentation(i))
                                          for i in range(pi.getNumOperands())))
                got = got.strip()
            except Exception as e:
                got = "PARSE FAIL " + str(e)[:60]
            norm = lambda s: s.lower().replace(" ", "").replace("0x0(", "0(")
            ok = norm(got) == norm(want_txt)
            allok &= ok
            print("  %-12s -> %-28s (wanted %-26s) %s"
                  % (hexb, got, want_txt, "PASS" if ok else "CHECK"))
        print()

        print("=== every reference to APP_rke_code_valid 0x40003F53 ===")
        a = af.getAddress(0x40003F53)
        w = r = 0
        for x in rm.getReferencesTo(a):
            s = x.getFromAddress()
            f = fm.getFunctionContaining(s)
            i = listing.getInstructionAt(s)
            t = str(x.getReferenceType())
            w += 1 if t == "WRITE" else 0
            print("   %s %-8s %-34s in %s" % (s, t, i,
                  f.getName() if f else "<unswept>"))
        print("   -> WRITE refs: %d" % w)
        print()

        print("=== callers of FUN_000AEEC6 / FUN_000AD97C / FUN_000ADE12 ===")
        for ent in (0x0AEEC6, 0x0AD97C, 0x0ADE12, 0x058538):
            aa = af.getAddress(ent)
            rr = list(rm.getReferencesTo(aa))
            print("  0x%06X : %d refs" % (ent, len(rr)))
            for x in rr:
                s = x.getFromAddress()
                f = fm.getFunctionContaining(s)
                print("      from %s %-20s in %s" % (
                    s, x.getReferenceType(), f.getName() if f else "<unswept>"))
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
