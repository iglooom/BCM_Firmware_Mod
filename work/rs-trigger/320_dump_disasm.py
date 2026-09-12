#!/usr/bin/env python3
"""Dump raw disassembly of 0x0AC000..0x0AE900 (the gate-word neighbourhood)
plus every reference to +0x94 of struct 0x400095EC, to a text file for
offline mask analysis.  Read-only.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

LO = 0x0AC000
HI = 0x0AF000
OUT = os.path.join(ROOT, "work/rs-trigger/logs/gate_disasm.txt")


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        lines = []
        a = af.getAddress(LO)
        end = af.getAddress(HI)
        ins = listing.getInstructionAt(a)
        if ins is None:
            ins = listing.getInstructionAfter(a)
        count = 0
        last = LO
        while ins is not None and ins.getAddress().getOffset() < HI:
            off = ins.getAddress().getOffset()
            if off > last:
                lines.append("---- GAP (no instruction) 0x%06X..0x%06X ----"
                             % (last, off))
            nb = ins.getLength()
            raw = ins.getBytes()
            hexb = "".join("%02X" % (b & 0xFF) for b in raw)
            f = fm.getFunctionContaining(ins.getAddress())
            fn = f.getName() if f else "UNSWEPT"
            ops = []
            for i in range(ins.getNumOperands()):
                ops.append(ins.getDefaultOperandRepresentation(i))
            lines.append("%06X %-10s %-10s %-40s ; %s"
                         % (off, hexb, ins.getMnemonicString(),
                            ", ".join(ops), fn))
            last = off + nb
            count += 1
            ins = listing.getInstructionAfter(ins.getAddress())
        with open(OUT, "w") as fh:
            fh.write("\n".join(lines))
        print("wrote %d instructions to %s" % (count, OUT))

        # also list functions in range
        print("\n== functions in range ==")
        it = fm.getFunctions(af.getAddress(LO), True)
        for f in it:
            e = f.getEntryPoint().getOffset()
            if e >= HI:
                break
            print("  %06X %s  body=%s" % (e, f.getName(), f.getBody()))
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
