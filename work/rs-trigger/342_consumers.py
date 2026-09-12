#!/usr/bin/env python3
"""342 -- the two consumers of APP_rke_code_valid 0x40003F53, in full.

Subject site A: 0x099308  bit 1  (absolute form) in FUN_000992fe  -- the RKE
                one-hot demux region (APP_rke_command_demux @0x0992B2 is
                adjacent).
Subject site B: 0x0AEEDA  bit 2  (base+disp form) in FUN_000aeec6  -- the
                0x0ADxxx/0x0AExxx REMOTE-START region that already contains the
                known consumers FUN_000ADADA (arms/times on enum 8) and
                FUN_000ADB1E (clears on release).

This script: decompiles both, disassembles 0x0AEEC0..0x0AEFC0 with resolved
references, and searches both function bodies for the documented enum-8 test
`(code & 0xF) == 8`.  Also walks callers of FUN_000aeec6 and FUN_000ADADA to
see whether they share a parent (they should if B is the RS entry).
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


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    monitor = ConsoleTaskMonitor()
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()
        di = DecompInterface()
        di.openProgram(program)

        print("===== DISASM 0x0AEEB0..0x0AEFA0 (consumer B) =====")
        ins = listing.getInstructionAt(af.getAddress(0x0AEEB0)) or \
            listing.getInstructionAfter(af.getAddress(0x0AEEB0))
        while ins is not None and ins.getAddress().getOffset() <= 0x0AEFA0:
            rs = " ".join("->%s(%s)" % (r.getToAddress(), r.getReferenceType())
                          for r in ins.getReferencesFrom())
            print("  %s  %-40s %s" % (ins.getAddress(), ins, rs))
            ins = listing.getInstructionAfter(ins.getAddress())

        for ent in (0x0AEEC6, 0x0ADADA, 0x0ADB1E):
            a = af.getAddress(ent)
            f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
            print("\n===== decompile 0x%06X =====" % ent)
            if not f:
                print("  <no function -- unswept block>")
                continue
            res = di.decompileFunction(f, 180, monitor)
            if res and res.decompileCompleted():
                print(res.getDecompiledFunction().getC())
            else:
                print("FAILED", res.getErrorMessage() if res else "")

        print("\n===== references TO the three functions (CALL+JUMP accepted) =====")
        for ent in (0x0AEEC6, 0x0ADADA, 0x0ADB1E, 0x0992FE):
            a = af.getAddress(ent)
            rr = [r for r in rm.getReferencesTo(a)]
            print(" 0x%06X : %d refs" % (ent, len(rr)))
            for r in rr:
                s = r.getFromAddress()
                f = fm.getFunctionContaining(s)
                print("     from %s %-20s in %s" % (
                    s, r.getReferenceType(), f.getName() if f else "<unswept>"))

        print("\n===== refs to APP_rke_command_code 0x40002DA2 / word 0x40002DA0 =====")
        for tgt in (0x40002DA0, 0x40002DA2):
            a = af.getAddress(tgt)
            rr = list(rm.getReferencesTo(a))
            print(" 0x%08X : %d" % (tgt, len(rr)))
            for r in rr:
                s = r.getFromAddress()
                f = fm.getFunctionContaining(s)
                i = listing.getInstructionAt(s)
                print("     %s %-12s %-34s in %s" % (
                    s, r.getReferenceType(), i, f.getName() if f else "<unswept>"))
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
