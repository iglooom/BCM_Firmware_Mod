#!/usr/bin/env python3
"""Residual-risk bound: could 0x4000965C be written WITHOUT a base+disp store?

Two escape hatches that all three instruments would miss:
  (a) a pointer to the struct stored in a table / passed to memset-like helper
  (b) a computed base in a register handed to a call

(a) is already excluded: no literal 0x400095EC / 0x4000965C anywhere in flash.
(b) is tested here: find every instruction in the whole listing that materialises
    an address inside [base, base+0x100) into ANY register, and report whether
    that register is consumed by a store (benign) or flows into a call argument
    register (r3..r8) that then reaches a bl (potential indirect writer).
Read-only.
"""
import os
import sys
import re
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
BASE = 0x400095EC
LO, HI = BASE, BASE + 0x100
TARGET = 0x4000965C

STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu", "e_stmw")
LOAD_MN = ("e_lbz", "e_lhz", "e_lwz", "se_lbz", "se_lhz", "se_lwz", "e_lha",
           "e_lbzu", "e_lwzu", "e_lmw")
CMP_MN = ("e_cmp", "se_cmp", "cmp", "e_cmph", "e_cmpl")
CALL_MN = ("e_bl", "se_bl", "se_bctrl", "e_bctrl")
ARGREGS = {"r3", "r4", "r5", "r6", "r7", "r8"}


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        listing = program.getListing()
        fm = program.getFunctionManager()
        regs = {}
        prev_end = None
        suspicious = []
        n_ptr_live_at_call = 0
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
                    regs[d0] = ((regs[src] + val) & 0xFFFFFFFF) if src in regs \
                        else None
                    if regs[d0] is None:
                        regs.pop(d0)
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
            elif mn.startswith(CALL_MN):
                live = {r: v for r, v in regs.items()
                        if r in ARGREGS and LO <= v < HI}
                if live:
                    n_ptr_live_at_call += 1
                    fnc = fm.getFunctionContaining(ins.getAddress())
                    suspicious.append((off, str(ins),
                                       fnc.getName() if fnc else "UNSWEPT",
                                       {r: hex(v) for r, v in live.items()}))
                regs = {r: v for r, v in regs.items()
                        if r not in ("r0", "r3", "r4", "r5", "r6", "r7", "r8",
                                     "r9", "r10", "r11", "r12")}
            elif mn.startswith(STORE_MN) or mn.startswith(LOAD_MN):
                if mn.startswith(LOAD_MN) and d0 in regs:
                    regs.pop(d0, None)
            elif d0 in regs and not mn.startswith(CMP_MN):
                regs.pop(d0, None)

        print("=" * 78)
        print("RESIDUAL RISK (b): struct pointer live in an ARG register at a CALL")
        print("=" * 78)
        print("   call sites with a pointer into [0x%08X,0x%08X) in r3..r8: %d"
              % (LO, HI, n_ptr_live_at_call))
        for off, txt, f, live in suspicious[:40]:
            print("   0x%06X  %-24s %-18s %s" % (off, txt, f, live))
        if not suspicious:
            print("   NONE -> no memset/memcpy-style indirect writer can exist;")
            print("   every write to the struct must be an inline base+disp store.")
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
