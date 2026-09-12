#!/usr/bin/env python3
"""Find BULK writers of 0x4000965C: APP_memset/memcpy-style calls whose
[dst, dst+len) interval covers the cell.  These are invisible to EVERY
instruction-level store scanner (ref-manager, base+disp sweep, and p-code
CALLOTHER-store) because the store executes inside the helper, at an address
that has nothing to do with the struct.

Resolves r3(dst), r4(val), r5(len) at each call site by linear register
tracking with block-discontinuity reset (same engine as 314 method D).
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
TARGET = 0x4000965C
BULK = {0x0010DAB8: "APP_memset"}

CMP_MN = ("e_cmp", "se_cmp", "cmp", "e_cmph", "e_cmpl")
STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu", "e_stmw")
LOAD_MN = ("e_lbz", "e_lhz", "e_lwz", "se_lbz", "se_lhz", "se_lwz", "e_lha",
           "e_lbzu", "e_lwzu", "e_lmw")


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        listing = program.getListing()
        fm = program.getFunctionManager()
        regs = {}
        prev_end = None
        hits = []
        allcalls = []
        it = listing.getInstructions(True)
        while it.hasNext():
            ins = it.next()
            off = ins.getAddress().getOffset()
            if prev_end is not None and off != prev_end:
                regs = {}
            prev_end = off + ins.getLength()
            mn = ins.getMnemonicString().lower()
            try:
                d0 = ins.getDefaultOperandRepresentation(0).strip().lower()
            except Exception:
                d0 = ""
            if mn in ("e_lis", "se_lis", "lis"):
                try:
                    regs[d0] = (int(ins.getScalar(1).getValue()) << 16) & 0xFFFFFFFF
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("e_add16i", "e_addi", "addi", "se_addi"):
                try:
                    src = ins.getDefaultOperandRepresentation(1).strip().lower()
                    val = int(ins.getScalar(2).getValue())
                    if src in regs:
                        regs[d0] = (regs[src] + val) & 0xFFFFFFFF
                    else:
                        regs.pop(d0, None)
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("se_li", "e_li", "li", "e_lil"):
                try:
                    regs[d0] = int(ins.getScalar(1).getValue()) & 0xFFFFFFFF
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("se_mr", "mr", "e_mr"):
                try:
                    src = ins.getDefaultOperandRepresentation(1).strip().lower()
                    if src in regs:
                        regs[d0] = regs[src]
                    else:
                        regs.pop(d0, None)
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("e_bl", "se_bl"):
                tgt = None
                try:
                    for r in ins.getFlows():
                        tgt = r.getOffset()
                except Exception:
                    pass
                if tgt in BULK:
                    dst = regs.get("r3")
                    val = regs.get("r4")
                    ln = regs.get("r5")
                    fnc = fm.getFunctionContaining(ins.getAddress())
                    rec = (off, BULK[tgt], dst, val, ln,
                           fnc.getName() if fnc else "UNSWEPT")
                    allcalls.append(rec)
                    if dst is not None and ln is not None and \
                            dst <= TARGET < dst + ln:
                        hits.append(rec)
                regs = {r: v for r, v in regs.items()
                        if r not in ("r0", "r3", "r4", "r5", "r6", "r7", "r8",
                                     "r9", "r10", "r11", "r12")}
            elif mn.startswith(LOAD_MN):
                if d0 in regs:
                    regs.pop(d0, None)
            elif mn.startswith(STORE_MN):
                pass
            elif d0 in regs and not mn.startswith(CMP_MN):
                regs.pop(d0, None)

        print("=" * 78)
        print("BULK (memset-class) calls with FULLY RESOLVED dst+len: %d"
              % len([c for c in allcalls if c[2] is not None
                     and c[4] is not None]))
        print("total memset call sites seen: %d" % len(allcalls))
        print("=" * 78)
        print("\nCALLS WHOSE [dst,dst+len) COVERS 0x%08X : %d" % (TARGET,
                                                                 len(hits)))
        for off, nm, dst, val, ln, f in hits:
            print("   0x%06X  %s(0x%08X, %s, 0x%X)   in %s   -> covers +0x%X"
                  % (off, nm, dst, ("0x%X" % val) if val is not None else "?",
                     ln, f, TARGET - dst))
        print("\nAll resolved memset calls targeting the 0x40009xxx page:")
        for off, nm, dst, val, ln, f in allcalls:
            if dst is not None and 0x40009000 <= dst < 0x4000A000:
                print("   0x%06X  %s(0x%08X, %s, %s)  %s"
                      % (off, nm, dst,
                         ("0x%X" % val) if val is not None else "?",
                         ("0x%X" % ln) if ln is not None else "UNRESOLVED", f))
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
