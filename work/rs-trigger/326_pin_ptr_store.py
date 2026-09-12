#!/usr/bin/env python3
"""326 -- pin the EXACT store instruction of the pointer writer, and confirm
the 0x1136D0 -> FUN_00113ea8 argument binding.

FUN_00113ea8's Ghidra *function body* is only 2 instructions long (the linear
sweep split it), so 325's body-bounded dump printed nothing useful -- exactly
the unswept/split-block condition of AGENTS.md rule 14.  Dump LINEARLY instead.

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


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        print("=" * 78)
        print("A. FUN_00113ea8 LINEAR DUMP 0x113EA8..0x113F60")
        print("=" * 78)
        ins = listing.getInstructionAt(af.getAddress(0x113EA8))
        while ins is not None and ins.getAddress().getOffset() < 0x113F70:
            fn = fm.getFunctionContaining(ins.getAddress())
            print("   0x%06X  %-32s %s"
                  % (ins.getAddress().getOffset(), str(ins),
                     ("<%s>" % fn.getName()) if fn else "<UNSWEPT>"))
            ins = ins.getNext()

        print()
        print("=" * 78)
        print("B. CALL SITE 0x1136C8..0x1136E0 -- argument binding")
        print("=" * 78)
        ins = listing.getInstructionAt(af.getAddress(0x1136C0))
        while ins is not None and ins.getAddress().getOffset() < 0x113750:
            print("   0x%06X  %s"
                  % (ins.getAddress().getOffset(), str(ins)))
            ins = ins.getNext()

        print()
        print("=" * 78)
        print("C. Who else CALLS FUN_00113ea8?  (other cells written the")
        print("   same way => the pointer-writer form is used repeatedly)")
        print("=" * 78)
        refmgr = program.getReferenceManager()
        n = 0
        for r in refmgr.getReferencesTo(af.getAddress(0x113EA8)):
            fa = r.getFromAddress()
            i = listing.getInstructionAt(fa)
            fn = fm.getFunctionContaining(fa)
            print("   0x%06X  %-24s fn=%s  type=%s"
                  % (fa.getOffset(), str(i) if i else "-",
                     fn.getName() if fn else "UNSWEPT", r.getReferenceType()))
            n += 1
        print("   total callers: %d" % n)
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
