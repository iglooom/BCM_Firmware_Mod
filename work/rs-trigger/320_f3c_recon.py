#!/usr/bin/env python3
"""Recon: disassembly context around the two KNOWN writers of 0x40002F3C, and
around the control cell's writers, so the base-register derivation is grounded
rather than assumed (AGENTS.md rule 44 corollary).

Read-only.
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

SITES = [0x1135AE, 0x11378C, 0x0AD6C6, 0x0AD6D4, 0x09749A, 0x097974]


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        mem = program.getMemory()

        print("MEMORY BLOCKS")
        for b in mem.getBlocks():
            print("   %-20s %s - %s  %s%s%s" % (
                b.getName(), b.getStart(), b.getEnd(),
                "r" if b.isRead() else "-",
                "w" if b.isWrite() else "-",
                "x" if b.isExecute() else "-"))
        print("\nfunctions: %d" % fm.getFunctionCount())

        for s in SITES:
            a = af.getAddress(s)
            fn = fm.getFunctionContaining(a)
            print("\n==== 0x%06X  fn=%s ====" % (
                s, fn.getName() if fn else "NONE (unswept)"))
            # 14 instructions back
            cur = listing.getInstructionAt(a)
            if cur is None:
                print("   no instruction at address")
                continue
            back = []
            p = cur
            for _ in range(16):
                p = p.getPrevious()
                if p is None:
                    break
                back.append(p)
            for p in reversed(back):
                print("   0x%06X  %s" % (p.getAddress().getOffset(), p))
            print("  >0x%06X  %s" % (cur.getAddress().getOffset(), cur))
            n = cur
            for _ in range(4):
                n = n.getNext()
                if n is None:
                    break
                print("   0x%06X  %s" % (n.getAddress().getOffset(), n))
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


main()
