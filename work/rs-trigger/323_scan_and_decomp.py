#!/usr/bin/env python3
"""(a) program-wide scan for e_stw/e_lwz of displacement +0x94 whose base
register resolves to 0x400095EC; (b) decompile the functions of interest;
(c) p-code for se_bseti/se_bclri to confirm bit numbering.  Read-only.

Retries the project lock rather than forcing it.
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

STRUCT = 0x400095EC
PCODE_AT = [0x0ADA3C, 0x0ADA76, 0x0AC85C, 0x0AE7CC]
DECOMP = [0x0AD97C, 0x0ADADA, 0x0AD6C6, 0x0AC85E, 0x0AC488, 0x0AE7C0,
          0x0AE61E, 0x0AD888]

STORE_MN = ("e_stw", "se_stw")
LOAD_MN = ("e_lwz", "se_lwz")


def open_retry():
    for i in range(40):
        try:
            return GhidraProject.openProject(PROJ, NAME, True)
        except Exception as e:
            if "lock" not in str(e).lower():
                raise
            print("locked, retry %d ..." % i)
            sys.stdout.flush()
            time.sleep(20)
    raise SystemExit("project stayed locked")


def main():
    project = open_retry()
    program = project.openProgram("/", PROG, True)
    monitor = ConsoleTaskMonitor()
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        # ---- (a) program-wide sweep, register tracking scoped per basic run
        print("===== program-wide +0x94 accesses with base == 0x400095EC =====")
        regs = {}          # regname -> value
        cur_fn = None
        hits = []
        ins = listing.getInstructions(True)
        n = 0
        for i in ins:
            n += 1
            a = i.getAddress()
            f = fm.getFunctionContaining(a)
            fn = f.getName() if f else "UNSWEPT@%s" % a
            if fn != cur_fn:
                regs = {}
                cur_fn = fn
            mn = i.getMnemonicString()
            ops = [i.getDefaultOperandRepresentation(k)
                   for k in range(i.getNumOperands())]
            try:
                if mn in ("e_lis",) and len(ops) == 2:
                    regs[ops[0]] = (int(ops[1], 16) & 0xFFFF) << 16
                elif mn in ("e_add16i", "e_addi", "se_addi") and len(ops) >= 2:
                    src = ops[1] if len(ops) == 3 else ops[0]
                    imm = ops[-1]
                    neg = imm.startswith("-")
                    v = int(imm.lstrip("-"), 16)
                    if neg:
                        v = -v
                    if src in regs:
                        regs[ops[0]] = (regs[src] + v) & 0xFFFFFFFF
                    else:
                        regs.pop(ops[0], None)
                elif mn in ("se_mr",) and len(ops) == 2:
                    if ops[1] in regs:
                        regs[ops[0]] = regs[ops[1]]
                    else:
                        regs.pop(ops[0], None)
                elif (mn in STORE_MN or mn in LOAD_MN) and len(ops) == 2:
                    m = re.match(r"(-?0x[0-9a-fA-F]+)\((r\d+)\)$", ops[1])
                    if m:
                        d = int(m.group(1), 16)
                        base = m.group(2)
                        if d == 0x94 and regs.get(base) == STRUCT:
                            hits.append((a.getOffset(), mn, ops[0], base, fn))
                    # a store/load does not change the base reg
                else:
                    # anything writing operand 0 invalidates it
                    if ops and re.match(r"^r\d+$", ops[0]) and \
                       not mn.startswith("e_st") and not mn.startswith("se_st") \
                       and not mn.startswith("e_b") and not mn.startswith("se_b") \
                       and not mn.startswith("e_cmp") and not mn.startswith("se_cmp"):
                        regs.pop(ops[0], None)
            except Exception:
                regs.pop(ops[0] if ops else "", None)
        print("scanned %d instructions" % n)
        for h in hits:
            print("  0x%06X %-7s %-4s base=%-4s  %s" % h)
        print("  total %d" % len(hits))

        # ---- (c) p-code
        print("\n===== P-CODE =====")
        for a in PCODE_AT:
            i = listing.getInstructionAt(af.getAddress(a))
            if i is None:
                print("0x%06X: none" % a)
                continue
            print("0x%06X  %s" % (a, i.toString()))
            for op in i.getPcode():
                print("     " + str(op))

        # ---- (b) decompile
        di = DecompInterface()
        di.openProgram(program)
        for a in DECOMP:
            ad = af.getAddress(a)
            f = fm.getFunctionAt(ad) or fm.getFunctionContaining(ad)
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
