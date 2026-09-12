#!/usr/bin/env python3
"""346 - resolve the dirty-flag primitive + the intermediate RX-path nodes.

Nodes:
  0x031360  VOL_test_and_clear_dirty   <-- BIT SEMANTICS ARE THE CRUX
  0x0FB0EE / 0x0FB0D8                  (VOL_frame_arrived internals)
  0x0AEEC6  FUN_000aeec6               (0x40003F53 bit2 -> 0x400095E1)
  0x0AD97C  FUN_000ad97c               (0x400095E1 -> 0x40009680 bit 0x08000000)
  0x0AD6C6  FUN_000ad6c6               (context)
Also dump raw disassembly of 0x031360 and of the 0x0AEED4..0x0AEF20 window.

READ-ONLY.
"""
import os, sys, json, traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
OUT = os.path.join(REPO, "work/rs-trigger/logs")

NODES = [0x031360, 0x0FB0EE, 0x0FB0D8, 0x0AEEC6, 0x0AD97C]
DISASM = [(0x031360, 0x0313C0), (0x0AEED0, 0x0AEF30), (0x0ADA00, 0x0ADA90)]

project = None
try:
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    project = GhidraProject.openProject(PROJ, NAME, True)
    prog = project.openProgram("/", PROG, True)
    af = prog.getAddressFactory().getDefaultAddressSpace()
    fm = prog.getFunctionManager()
    listing = prog.getListing()
    di = DecompInterface(); di.openProgram(prog)
    mon = ConsoleTaskMonitor()

    for a in NODES:
        ad = af.getAddress(a)
        f = fm.getFunctionAt(ad) or fm.getFunctionContaining(ad)
        print("=" * 72)
        print("NODE", hex(a), f.getName() if f else "UNSWEPT")
        print("=" * 72)
        if f:
            r = di.decompileFunction(f, 120, mon)
            print(r.getDecompiledFunction().getC() if r.decompileCompleted()
                  else "FAIL " + str(r.getErrorMessage()))

    for lo, hi in DISASM:
        print("#" * 72)
        print("DISASM %06X..%06X" % (lo, hi))
        print("#" * 72)
        ii = listing.getInstructions(af.getAddress(lo), True)
        for ins in ii:
            off = ins.getAddress().getOffset()
            if off >= hi:
                break
            print("  %06X  %s" % (off, ins))

except Exception:
    traceback.print_exc()
    sys.stdout.flush(); sys.stderr.flush()
finally:
    try:
        if project is not None:
            project.close()
    except Exception:
        traceback.print_exc()
    sys.stdout.flush(); sys.stderr.flush()
    os._exit(0)
