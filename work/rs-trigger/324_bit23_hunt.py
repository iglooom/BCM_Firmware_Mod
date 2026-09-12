#!/usr/bin/env python3
"""Exhaustive hunt for writers of bits 0x00800000 / 0x04000000 / 0x08000000 of
DAT_40009680 (= struct 0x400095EC field +0x94).

(a) every instruction in the image with displacement 0x94 on a load/store word
    (no base-value requirement -- report base + containing function);
(b) every reference Ghidra knows to 0x40009680;
(c) decompile FUN_000acb92, FUN_000ad888 and whatever contains 0x0ADA3E,
    plus callers of the bit-27 producer.
Read-only, lock-retrying.
"""
import os
import re
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
CELL = 0x40009680


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

        print("===== (b) Ghidra references to 0x%08X =====" % CELL)
        for r in rm.getReferencesTo(af.getAddress(CELL)):
            fa = r.getFromAddress()
            f = fm.getFunctionContaining(fa)
            i = listing.getInstructionAt(fa)
            print("  0x%06X %-16s %-40s %s"
                  % (fa.getOffset(), r.getReferenceType(),
                     i.toString() if i else "?",
                     f.getName() if f else "UNSWEPT"))

        print("\n===== (a) every word load/store with disp 0x94 =====")
        rex = re.compile(r"^(-?0x[0-9a-fA-F]+)\((r\d+)\)$")
        hits = []
        for i in listing.getInstructions(True):
            mn = i.getMnemonicString()
            if mn not in ("e_stw", "e_lwz", "se_stw", "se_lwz"):
                continue
            if i.getNumOperands() != 2:
                continue
            o1 = i.getDefaultOperandRepresentation(1)
            m = rex.match(o1)
            if not m or int(m.group(1), 16) != 0x94:
                continue
            a = i.getAddress()
            f = fm.getFunctionContaining(a)
            hits.append((a.getOffset(), mn,
                         i.getDefaultOperandRepresentation(0), m.group(2),
                         f.getName() if f else "UNSWEPT"))
        for h in hits:
            print("  0x%06X %-7s %-5s base=%-5s %s" % h)
        print("  total %d" % len(hits))

        # (c) decompiles
        di = DecompInterface()
        di.openProgram(program)
        targets = [0x0ACB92, 0x0AD888, 0x0ADA3E, 0x0AC8A8, 0x0AE820]
        # add callers of the function containing 0x0ADA3E
        fa = fm.getFunctionContaining(af.getAddress(0x0ADA3E))
        if fa:
            print("\nfunction containing 0x0ADA3E: %s @ %s body=%s"
                  % (fa.getName(), fa.getEntryPoint(), fa.getBody()))
            for c in fa.getCallingFunctions(monitor):
                print("  caller: %s @ %s" % (c.getName(), c.getEntryPoint()))
                targets.append(c.getEntryPoint().getOffset())
        seen = set()
        for a in targets:
            if a in seen:
                continue
            seen.add(a)
            ad = af.getAddress(a)
            f = fm.getFunctionAt(ad) or fm.getFunctionContaining(ad)
            if not f:
                print("\n===== no fn at 0x%06X =====" % a)
                continue
            res = di.decompileFunction(f, 150, monitor)
            print("\n========== %s @ %s ==========" % (f.getName(),
                                                       f.getEntryPoint()))
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
