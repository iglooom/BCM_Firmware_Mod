#!/usr/bin/env python3
"""Raw disassembly of 0x0AEEC0..0x0AEF80 (the producer of 0x400095E1) and
0x0AE900..0x0AEB00 (the bit-0x00800000 sites), plus the callee names.
Read-only, lock-retrying.
"""
import os
import sys
import time
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

RANGES = [(0x0AEEC6, 0x0AEF80), (0x0AE900, 0x0AEA00),
          (0x0AD888, 0x0AD960)]


def open_retry():
    for i in range(60):
        try:
            return GhidraProject.openProject(PROJ, NAME, True)
        except Exception as e:
            if "lock" not in str(e).lower():
                raise
            print("locked %d" % i)
            sys.stdout.flush()
            time.sleep(20)
    raise SystemExit("locked")


def main():
    project = open_retry()
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        sym = program.getSymbolTable()
        for lo, hi in RANGES:
            print("\n===== 0x%06X .. 0x%06X =====" % (lo, hi))
            i = listing.getInstructionAt(af.getAddress(lo)) or \
                listing.getInstructionAfter(af.getAddress(lo))
            while i is not None and i.getAddress().getOffset() < hi:
                off = i.getAddress().getOffset()
                ops = ", ".join(i.getDefaultOperandRepresentation(k)
                                for k in range(i.getNumOperands()))
                extra = ""
                for r in i.getReferencesFrom():
                    t = r.getToAddress()
                    s = sym.getPrimarySymbol(t)
                    fn = fm.getFunctionAt(t)
                    if fn:
                        extra += "  -> %s" % fn.getName()
                    elif s:
                        extra += "  -> %s" % s.getName()
                f = fm.getFunctionContaining(i.getAddress())
                print("%06X %-10s %-42s ; %s%s"
                      % (off, i.getMnemonicString(), ops,
                         f.getName() if f else "UNSWEPT", extra))
                i = listing.getInstructionAfter(i.getAddress())
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
