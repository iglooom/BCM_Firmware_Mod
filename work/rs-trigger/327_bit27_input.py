#!/usr/bin/env python3
"""Who writes byte 0x400095E1 (= r3+5, the sole data input of the
0x08000000 producer at 0x0ADA3E)?  And what writes 0x400095DC..0x400095E3?

Uses the reference manager plus a per-function base+displacement sweep.
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

CELLS = list(range(0x400095DC, 0x400095E8))
STRUCT2 = 0x400095DC
LOADS = ("e_lbz", "se_lbz", "e_lhz", "se_lhz", "e_lwz", "se_lwz")
STORES = ("e_stb", "se_stb", "e_sth", "se_sth", "e_stw", "se_stw")


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

        print("===== reference manager: refs to 0x400095DC..0x400095E7 =====")
        for c in CELLS:
            for r in rm.getReferencesTo(af.getAddress(c)):
                fa = r.getFromAddress()
                f = fm.getFunctionContaining(fa)
                i = listing.getInstructionAt(fa)
                print("  0x%08X <- 0x%06X %-14s %-32s %s"
                      % (c, fa.getOffset(), r.getReferenceType(),
                         i.toString() if i else "?",
                         f.getName() if f else "UNSWEPT"))

        print("\n===== per-function sweep: base==0x400095DC accesses =====")
        rex = re.compile(r"(-?0x[0-9a-fA-F]+)\((r\d+)\)$")
        regs = {}
        cur = None
        for i in listing.getInstructions(True):
            a = i.getAddress()
            f = fm.getFunctionContaining(a)
            fn = f.getName() if f else "UNSWEPT"
            if fn != cur:
                regs = {}
                cur = fn
            mn = i.getMnemonicString()
            ops = [i.getDefaultOperandRepresentation(k)
                   for k in range(i.getNumOperands())]
            if not ops:
                continue
            try:
                if mn == "e_lis":
                    regs[ops[0]] = (int(ops[1], 16) & 0xFFFF) << 16
                elif mn in ("e_add16i", "e_addi") and len(ops) == 3:
                    s = ops[1]
                    v = int(ops[2].lstrip("-"), 16)
                    if ops[2].startswith("-"):
                        v = -v
                    if s in regs:
                        regs[ops[0]] = (regs[s] + v) & 0xFFFFFFFF
                    else:
                        regs.pop(ops[0], None)
                elif (mn in LOADS or mn in STORES) and len(ops) == 2:
                    m = rex.match(ops[1])
                    if m:
                        d = int(m.group(1), 16)
                        b = regs.get(m.group(2))
                        if b is not None and STRUCT2 <= b + d <= STRUCT2 + 7:
                            print("  0x%06X %-7s %-5s -> 0x%08X  %s"
                                  % (a.getOffset(), mn, ops[0], b + d, fn))
                else:
                    if re.match(r"^r\d+$", ops[0]) and \
                       not mn.startswith(("e_st", "se_st", "e_b", "se_b",
                                          "e_cmp", "se_cmp")):
                        regs.pop(ops[0], None)
            except Exception:
                regs.pop(ops[0], None)
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
