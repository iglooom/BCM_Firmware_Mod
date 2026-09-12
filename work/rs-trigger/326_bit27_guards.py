#!/usr/bin/env python3
"""Guards for the bit-27 producer and the bit-23 sites.

Decompiles the fragments that own 0x0ADA3E's logical function and the
0x0AE922/0x0AE958 bit-23 region, and finds every call/jump INTO the
0x0AD754..0x0ADAD9 span so param_1 can be identified.
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
from ghidra.app.decompiler import DecompInterface  # noqa: E402
from ghidra.util.task import ConsoleTaskMonitor  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

SPAN = (0x0AD6C6, 0x0ADAD9)
DECOMP = [0x0AD754, 0x0AD7D4, 0x0AD888, 0x0AE922, 0x0AE958, 0x0AEBCC,
          0x0AE5E0, 0x0AE61E, 0x0AE7C0, 0x0AE6F8, 0x0AC488]


def open_retry():
    for i in range(60):
        try:
            return GhidraProject.openProject(PROJ, NAME, True)
        except Exception as e:
            if "lock" not in str(e).lower():
                raise
            print("locked, retry %d" % i)
            sys.stdout.flush()
            time.sleep(20)
    raise SystemExit("locked")


def main():
    project = open_retry()
    program = project.openProgram("/", PROG, True)
    monitor = ConsoleTaskMonitor()
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        print("===== references INTO 0x%06X..0x%06X from outside ====="
              % SPAN)
        for a in range(SPAN[0], SPAN[1] + 1, 2):
            ad = af.getAddress(a)
            for r in rm.getReferencesTo(ad):
                fa = r.getFromAddress().getOffset()
                if SPAN[0] <= fa <= SPAN[1]:
                    continue
                f = fm.getFunctionContaining(r.getFromAddress())
                i = listing.getInstructionAt(r.getFromAddress())
                print("  ->0x%06X from 0x%06X %-14s %-32s %s"
                      % (a, fa, r.getReferenceType(),
                         i.toString() if i else "?",
                         f.getName() if f else "UNSWEPT"))

        di = DecompInterface()
        di.openProgram(program)
        for a in DECOMP:
            ad = af.getAddress(a)
            f = fm.getFunctionAt(ad) or fm.getFunctionContaining(ad)
            if not f:
                print("\n===== no fn at 0x%06X =====" % a)
                continue
            res = di.decompileFunction(f, 150, monitor)
            print("\n========== %s @ %s body=%s =========="
                  % (f.getName(), f.getEntryPoint(), f.getBody()))
            if res and res.decompileCompleted():
                print(res.getDecompiledFunction().getC())
            else:
                print("FAILED")
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
