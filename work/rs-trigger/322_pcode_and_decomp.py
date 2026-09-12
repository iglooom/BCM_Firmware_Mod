#!/usr/bin/env python3
"""Resolve se_bseti/se_bclri bit-numbering from Ghidra p-code, and decompile
the key functions around the +0x94 gate word.  Read-only.
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
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

PCODE_AT = [0x0ADA3C, 0x0ADA76, 0x0AC528, 0x0AC51A, 0x0ADB66, 0x0AE7CC,
            0x0ADA34, 0x0ADA3E]
DECOMP = [0x0AD97C, 0x0ADADA, 0x0AD6C6, 0x0AC508, 0x0AD924, 0x0AC488,
          0x0ADB98, 0x0AE7C0]


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    monitor = ConsoleTaskMonitor()
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        print("===== P-CODE (resolves se_bseti/se_bclri bit numbering) =====")
        for a in PCODE_AT:
            ins = listing.getInstructionAt(af.getAddress(a))
            if ins is None:
                print("0x%06X: no instruction" % a)
                continue
            print("0x%06X  %s %s" % (a, ins.getMnemonicString(),
                                     ins.toString()))
            for op in ins.getPcode():
                print("     " + str(op))
            print()

        di = DecompInterface()
        di.openProgram(program)
        for a in DECOMP:
            f = fm.getFunctionAt(af.getAddress(a)) or \
                fm.getFunctionContaining(af.getAddress(a))
            if not f:
                print("\n===== no function at 0x%06X =====" % a)
                continue
            res = di.decompileFunction(f, 120, monitor)
            print("\n========== %s @ %s ==========" % (f.getName(),
                                                       f.getEntryPoint()))
            if res and res.decompileCompleted():
                print(res.getDecompiledFunction().getC())
            else:
                print("FAILED:", res.getErrorMessage() if res else "none")
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
