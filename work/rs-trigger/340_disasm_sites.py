#!/usr/bin/env python3
"""340 -- raw disassembly around the key VOL_test_and_clear_dirty call sites,
plus every reference to 0x40003F53 including p-code-visible ones.

Purpose: (a) adjudicate why CONTROL C1 (0x40003FC0 bit 4 in APP_tx_compose)
failed in 339 -- is the documented form actually a DIFFERENT addressing form
(descriptor pointer + indirect flag pointer at desc+4/+8) rather than an
absolute flag pointer?  (b) confirm the subject site 0x099308 byte-for-byte.
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

WINDOWS = [
    ("subject  demux-region site", 0x0992D0, 0x099340),
    ("control2 0x40003FF1 bit2", 0x0AE900, 0x0AE960),
    ("control1? tx_compose lock", 0x04C610, 0x04C6B0),
    ("commit sets valid byte", 0x058538, 0x0585A0),
]


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    monitor = ConsoleTaskMonitor()
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        for label, lo, hi in WINDOWS:
            print("\n===== %s : 0x%06X..0x%06X =====" % (label, lo, hi))
            a = af.getAddress(lo)
            end = af.getAddress(hi)
            ins = listing.getInstructionAt(a) or listing.getInstructionAfter(a)
            while ins is not None and ins.getAddress().getOffset() <= hi:
                refs = ins.getReferencesFrom()
                rs = " ".join("->%s(%s)" % (r.getToAddress(), r.getReferenceType())
                              for r in refs)
                print("  %s  %-40s %s" % (ins.getAddress(), ins, rs))
                ins = listing.getInstructionAfter(ins.getAddress())

        print("\n===== bytes of the SET at commit (0x40003F53 = 0xFF) =====")
        for tgt in (0x40003F53,):
            a = af.getAddress(tgt)
            for x in rm.getReferencesTo(a):
                s = x.getFromAddress()
                f = fm.getFunctionContaining(s)
                i = listing.getInstructionAt(s)
                print("  %s %-16s %-40s in %s" % (
                    s, x.getReferenceType(), i, f.getName() if f else "<unswept>"))

        print("\n===== decompile FUN_000992fe (subject consumer) =====")
        di = DecompInterface()
        di.openProgram(program)
        for ent in (0x0992FE, 0x0992B2):
            f = fm.getFunctionAt(af.getAddress(ent)) or \
                fm.getFunctionContaining(af.getAddress(ent))
            if not f:
                print("no function at 0x%X" % ent)
                continue
            res = di.decompileFunction(f, 120, monitor)
            print("---- %s @ %s ----" % (f.getName(), f.getEntryPoint()))
            if res and res.decompileCompleted():
                print(res.getDecompiledFunction().getC())
            else:
                print("FAILED", res.getErrorMessage() if res else "")
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
