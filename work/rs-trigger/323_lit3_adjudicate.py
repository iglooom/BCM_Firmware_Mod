#!/usr/bin/env python3
"""323 -- ADJUDICATE the literal-3 candidates.

322's method D found 4 sites in the image where a register holding LITERAL 3 is
byte-stored at displacement 0xC:

    0x077DB4  se_stb r?,0xc(r6)
    0x077E02  se_stb r?,0xc(r6)
    0x077F78  se_stb r?,0xc(r27)
    0x0F6754  se_stb r?,0xc(r1)

Three of them are inside 0x077xxx -- the SAME neighbourhood as two of the
target's KNOWN READ SITES (0x077EFE, 0x077FB4).  If any of those base registers
holds 0x40002F30, then literal 3 IS written to 0x40002F3C and the "state 3 is
unreachable" conclusion collapses.  Methods A/B/C all missed them, so their
agreement at 2 would be a shared blind spot, not a confirmation.

This resolves each base with Ghidra (which has the full function context the raw
linear tracker lacks) and prints the surrounding code plus the decompilation.

Also: locate the 0x40002D20 struct's OTHER base-register aliases.  A struct
field can be reached from ANY base whose value + disp lands on the cell, so the
complete question is "which registers ever hold a value V with
V + disp == 0x40002F3C for some store".  This enumerates every distinct base
value that reaches the cell anywhere in the image (method B's tracker data).

Read-only.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.app.decompiler import DecompInterface  # noqa: E402
from ghidra.util.task import ConsoleTaskMonitor  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")

CANDS = [0x077DB4, 0x077E02, 0x077F78, 0x0F6754]
READS = [0x077EFE, 0x077FB4, 0x04E208, 0x051264, 0x05A15E, 0x0AD6D4]


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        refmgr = program.getReferenceManager()

        print("=" * 78)
        print("PART 1 -- the four literal-3 candidates: what is the base?")
        print("=" * 78)
        for c in CANDS:
            a = af.getAddress(c)
            fn = fm.getFunctionContaining(a)
            print("\n---- 0x%06X   fn=%s ----"
                  % (c, fn.getName() if fn else "UNSWEPT"))
            ins = listing.getInstructionAt(a)
            if ins is None:
                print("   NOT an instruction boundary in Ghidra's"
                      " disassembly -- raw-scan false positive")
                # show what Ghidra thinks is there
                for d in (-2, -1, 0):
                    p = listing.getInstructionContaining(
                        af.getAddress(c + d))
                    if p is not None:
                        print("   containing instruction: 0x%06X  %s"
                              % (p.getAddress().getOffset(), p))
                        break
                continue
            # walk back for the base definition
            p = ins
            hist = []
            for _ in range(40):
                p = p.getPrevious()
                if p is None:
                    break
                hist.append(p)
            for p in reversed(hist[:24]):
                print("   0x%06X  %s" % (p.getAddress().getOffset(), p))
            print("  >0x%06X  %s   <== candidate"
                  % (c, ins))
            n = ins
            for _ in range(3):
                n = n.getNext()
                if n is None:
                    break
                print("   0x%06X  %s" % (n.getAddress().getOffset(), n))
            # any reference Ghidra attached to it?
            rs = list(refmgr.getReferencesFrom(a))
            print("   ghidra refs from this instruction: %s"
                  % ([str(r.getToAddress()) for r in rs] or "none"))

        # ------------------------------------------------------------------
        print()
        print("=" * 78)
        print("PART 2 -- decompilation of the functions holding the")
        print("          candidates and the 0x077xxx read sites")
        print("=" * 78)
        di = DecompInterface()
        di.openProgram(program)
        mon = ConsoleTaskMonitor()
        done = set()
        for c in CANDS + READS:
            a = af.getAddress(c)
            fn = fm.getFunctionContaining(a)
            if fn is None:
                print("\n### 0x%06X : UNSWEPT, no function" % c)
                continue
            key = fn.getEntryPoint().getOffset()
            if key in done:
                print("\n### 0x%06X -> %s (already printed)" % (c, fn.getName()))
                continue
            done.add(key)
            res = di.decompileFunction(fn, 90, mon)
            print("\n########## 0x%06X in %s @0x%06X ##########"
                  % (c, fn.getName(), key))
            if res and res.decompileCompleted():
                txt = res.getDecompiledFunction().getC()
                print(txt)
            else:
                print("   decompile failed")
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
