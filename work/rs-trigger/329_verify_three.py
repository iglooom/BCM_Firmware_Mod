#!/usr/bin/env python3
"""329 -- FINAL VERIFICATION that literal 3 reaches 0x40002F3C.

Chain (each link verified at instruction level, not from the decompiler alone):

 1. FUN_0011367e @0x1136CC-0x1136DA
       e_add16i r31,r30,0x210      r30=0x40002D20 -> r31=0x40002F30
       e_add16i r5 ,r30,0x21c      ->  r5 = 0x40002F3C  (= param_3)
       se_li    r3,0x1             ->  param_1 = 1 (channel index)
       e_bl     0x00113ea8
 2. FUN_00113ea8 @0x113EB0  se_mr r6,r5                 r6 = &DAT_40002F3C
                  @0x113F3A-0x113F40  r5 = idx*0xE
                  @0x113F42-0x113F4A  r7 = 0x4000B0B0 + idx*0xE
                  @0x113F4C  se_lbz r5,0xb(r7)     src = arr[idx].byte_0xB
                  @0x113F58  e_andi r7,r5,0x3
                  @0x113F5E  se_stb r7,0x0(r6)     *0x40002F3C = src & 3
 3. src byte literals written elsewhere (327/328):
       0x64 -> &3 = 0     0x69 -> &3 = 1
       0x8F -> &3 = 3 ***  0x93 -> &3 = 3 ***  0x57 -> &3 = 3 ***

=> 3 IS stored.  This script re-reads every one of those literals from the
instruction stream so the verdict does not rest on decompiler output.

Read-only.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")

# every site 327/328 reported as writing arr[idx] byte +0xB
SRC_WRITERS = [0x113A36, 0x113A82, 0x113AB4, 0x113B50, 0x113C5C,
               0x113D6C, 0x113FEA, 0x113FFE]
STORE_MN = ("e_stb", "se_stb", "e_sth", "se_sth", "e_stw", "se_stw")


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        print("=" * 78)
        print("SOURCE-BYTE WRITERS: literal, and literal & 3")
        print("=" * 78)
        vals = set()
        for s in SRC_WRITERS:
            a = af.getAddress(s)
            ins = listing.getInstructionAt(a)
            if ins is None:
                print("   0x%06X  not an instruction" % s)
                continue
            src = ins.getDefaultOperandRepresentation(0).strip().lower()
            p = ins
            prod, lit = None, None
            for _ in range(25):
                p = p.getPrevious()
                if p is None:
                    break
                pm = p.getMnemonicString().lower()
                try:
                    pd = p.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    pd = ""
                if pd == src and not pm.startswith(
                        STORE_MN + ("e_cmp", "se_cmp", "e_b", "se_b")):
                    prod = p
                    if pm in ("se_li", "e_li", "li"):
                        try:
                            lit = int(p.getScalar(1).getValue())
                        except Exception:
                            pass
                    break
            fn = fm.getFunctionContaining(a)
            if lit is not None:
                vals.add(lit & 3)
                mark = "  <<<=== &3 == 3, THE GATE VALUE" if (lit & 3) == 3 \
                    else ""
                print("   0x%06X %-22s <- %-26s literal 0x%02X (%d)"
                      "  &3 = %d%s"
                      % (s, str(ins), str(prod), lit, lit, lit & 3, mark))
            else:
                print("   0x%06X %-22s <- %-26s NOT a literal (computed)"
                      % (s, str(ins), str(prod)))
            del fn

        print()
        print("   distinct (literal & 3) values stored into 0x40002F3C via")
        print("   the pointer writer: %s" % sorted(vals))
        print("   3 present: %s" % (3 in vals))

        print()
        print("=" * 78)
        print("INSTRUCTION-LEVEL RE-READ OF THE WHOLE CHAIN")
        print("=" * 78)
        for lo, hi, tag in [(0x1136CC, 0x1136DE, "caller arg setup"),
                            (0x113EB0, 0x113EB4, "r6 = param_3"),
                            (0x113F3A, 0x113F62, "index math + the store")]:
            print("\n   -- %s --" % tag)
            ins = listing.getInstructionAt(af.getAddress(lo))
            while ins is not None and ins.getAddress().getOffset() < hi:
                print("      0x%06X  %s"
                      % (ins.getAddress().getOffset(), ins))
                ins = ins.getNext()
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


main()
