#!/usr/bin/env python3
"""343 -- close the chain:  0x40003F53 bit2 --tac@0x0AEEDA--> 0x4000968B
--> 0x400095E1 --guard--> the remote-start bit-27 setter @0x0ADA3E in
FUN_000AD97C.

Also enumerate EVERY reader/writer of 0x400095E1 and 0x4000968B, disassemble
0x0ADA10..0x0ADA90 (the bit-27 setter and its guard), and dump the 0x0AD97C
decompile.

POSITIVE CONTROL for the reference scan: 0x400095E2 -- the byte immediately
after the subject, written by the SAME function (0x0AEF20) from the SAME
test-and-clear idiom (flag 0x40003F54 bit 2), i.e. same region AND same
addressing form (se_stb rX, disp(r25)).  If 0x400095E2 shows no refs, the scan
is blind and the result is INCONCLUSIVE.
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

        print("SCAN SCOPE: whole program, all memory blocks "
              "(CFLASH 0..0x17FFFF, SRAM 0x40000000..0x40017FFF, etc.)\n")

        for tgt, label in ((0x400095E1, "SUBJECT  arrival byte"),
                           (0x400095E2, "CONTROL  sibling byte"),
                           (0x4000968B, "SUBJECT  staging byte"),
                           (0x4000968C, "CONTROL  staging sibling")):
            a = af.getAddress(tgt)
            rr = list(rm.getReferencesTo(a))
            print("=== 0x%08X  %s : %d refs ===" % (tgt, label, len(rr)))
            for r in rr:
                s = r.getFromAddress()
                f = fm.getFunctionContaining(s)
                i = listing.getInstructionAt(s)
                print("    %s %-8s %-34s in %s" % (
                    s, r.getReferenceType(), i,
                    f.getName() if f else "<unswept>"))
            if len(rr) == 0:
                print("    (none)")
            print()

        print("===== DISASM 0x0ADA00..0x0ADA90 (bit-27 setter + guard) =====")
        ins = listing.getInstructionAt(af.getAddress(0x0ADA00)) or \
            listing.getInstructionAfter(af.getAddress(0x0ADA00))
        while ins is not None and ins.getAddress().getOffset() <= 0x0ADA90:
            rs = " ".join("->%s(%s)" % (r.getToAddress(), r.getReferenceType())
                          for r in ins.getReferencesFrom())
            print("  %s  %-40s %s" % (ins.getAddress(), ins, rs))
            ins = listing.getInstructionAfter(ins.getAddress())

        print("\n===== DISASM 0x058560..0x058574 (the SET) with raw bytes =====")
        mem = program.getMemory()
        ins = listing.getInstructionAt(af.getAddress(0x058560))
        while ins is not None and ins.getAddress().getOffset() <= 0x058574:
            b = bytes([mem.getByte(ins.getAddress().add(i)) & 0xFF
                       for i in range(ins.getLength())])
            print("  %s  %-12s %-40s" % (ins.getAddress(), b.hex(), ins))
            ins = listing.getInstructionAfter(ins.getAddress())

        di = DecompInterface()
        di.openProgram(program)
        for ent in (0x0AD97C,):
            f = fm.getFunctionAt(af.getAddress(ent)) or \
                fm.getFunctionContaining(af.getAddress(ent))
            print("\n===== decompile 0x%06X =====" % ent)
            if not f:
                print("  <no function>")
                continue
            res = di.decompileFunction(f, 180, monitor)
            print(res.getDecompiledFunction().getC() if res and
                  res.decompileCompleted() else "FAILED")
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
