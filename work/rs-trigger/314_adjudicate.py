#!/usr/bin/env python3
"""Adjudicate 311 (6 sites) vs 313 (3 sites) on 0x4000965C.

Phase 1  context: dump disassembly around each of the 6 known sites, showing
         function containment and the provenance of the base register, so the
         exact reason 313's per-function tracker fails can be named.
Phase 2  method C: decompiler p-code.  Rule 14: memory ops are CALLOTHER
         userops, 0x10000002=store, 0x10000001=load -- NOT PcodeOp.STORE.
Phase 3  method D: WHOLE-LISTING linear sweep (not scoped to
         FunctionManager.getFunctions()), register state reset at every
         instruction that is not fall-through-reachable from its predecessor.
         This is the only instrument that can see UNSWEPT blocks.

Read-only.
"""
import os
import sys
import re
import traceback
from collections import defaultdict

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.app.decompiler import DecompInterface  # noqa: E402
from ghidra.util.task import ConsoleTaskMonitor  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")

TARGET = 0x4000965C
KNOWN = [0x0AD700, 0x0AD738, 0x0AD762, 0x0AE8D4, 0x0AEB88, 0x0AEBE0]

STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu", "e_stmw")
CMP_MN = ("e_cmp", "se_cmp", "cmp", "e_cmph", "e_cmpl")
BRANCH_MN = ("e_b", "se_b", "e_bc", "se_bc", "se_bl", "e_bl", "se_blr",
             "se_bctr", "se_rfi", "se_isync")

# scan window: the whole image, but the struct is app-block; keep it honest by
# sweeping every defined instruction in the program.


def parse_disp(txt):
    m = re.match(r"(-?)0x([0-9a-fA-F]+)\((r\d+)\)", txt)
    if m:
        s, mag, reg = m.groups()
        return (-int(mag, 16) if s == "-" else int(mag, 16)), reg
    m = re.match(r"(-?)(\d+)\((r\d+)\)", txt)
    if m:
        s, mag, reg = m.groups()
        return (-int(mag) if s == "-" else int(mag)), reg
    return None, None


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        # ------------------------------------------------------------------
        print("=" * 78)
        print("PHASE 1  CONTEXT OF THE 6 KNOWN SITES")
        print("=" * 78)
        for site in KNOWN:
            a = af.getAddress(site)
            fn = fm.getFunctionContaining(a)
            print("\n--- 0x%06X  fn=%s" % (
                site, fn.getName() if fn else "NONE (UNSWEPT BLOCK)"))
            if fn is not None:
                b = fn.getBody()
                print("    body %s .. %s  numAddrRanges=%d"
                      % (b.getMinAddress(), b.getMaxAddress(),
                         b.getNumAddressRanges()))
            ins = listing.getInstructionAt(a)
            try:
                tgt = ins.getDefaultOperandRepresentation(1).strip().lower()
            except Exception:
                tgt = ""
            disp, basereg = parse_disp(tgt)
            print("    store: %s   base=%s disp=%s" % (str(ins), basereg, disp))
            # walk back looking for the definition of basereg
            cur = ins.getPrevious()
            n = 0
            trail = []
            while cur is not None and n < 60:
                n += 1
                mn = cur.getMnemonicString().lower()
                try:
                    d0 = cur.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    d0 = ""
                trail.append("      -%2d 0x%06X %s" % (n,
                             cur.getAddress().getOffset(), str(cur)))
                if d0 == basereg and not mn.startswith(STORE_MN + CMP_MN
                                                       + BRANCH_MN):
                    print("    base %s DEFINED %d back: 0x%06X %s"
                          % (basereg, n, cur.getAddress().getOffset(),
                             str(cur)))
                    break
                cur = cur.getPrevious()
            else:
                print("    base %s NOT defined within 60 instructions back"
                      % basereg)
            print("\n".join(trail[:14]))

        # ------------------------------------------------------------------
        print()
        print("=" * 78)
        print("PHASE 2  METHOD C -- DECOMPILER P-CODE (CALLOTHER 0x10000002)")
        print("=" * 78)
        ifc = DecompInterface()
        ifc.openProgram(program)
        mon = ConsoleTaskMonitor()
        C = []
        # candidate functions: any function whose body touches the app region
        # that references the struct base at all.  Decompile the region
        # 0x0A0000-0x0B4000 exhaustively (superset of every known site).
        LO, HI = 0x0A0000, 0x0B4000
        cand = []
        for fn in fm.getFunctions(True):
            mn_ = fn.getBody().getMinAddress().getOffset()
            if LO <= mn_ < HI:
                cand.append(fn)
        print("   decompiling %d functions in 0x%06X-0x%06X ..."
              % (len(cand), LO, HI))
        ndec = 0
        for fn in cand:
            try:
                res = ifc.decompileFunction(fn, 60, mon)
                hf = res.getHighFunction()
                if hf is None:
                    continue
                ndec += 1
                for op in hf.getPcodeOps():
                    if op.getMnemonic() != "CALLOTHER":
                        continue
                    ins0 = op.getInput(0)
                    if ins0 is None or not ins0.isConstant():
                        continue
                    if ins0.getOffset() != 0x10000002:
                        continue
                    # remaining inputs: address expression, value
                    for i in range(1, op.getNumInputs()):
                        v = op.getInput(i)
                        if v is not None and v.isConstant() \
                                and v.getOffset() == TARGET:
                            C.append((op.getSeqnum().getTarget().getOffset(),
                                      fn.getName()))
                            break
                    else:
                        # address may be a varnode in the ram space
                        for i in range(1, op.getNumInputs()):
                            v = op.getInput(i)
                            if v is None:
                                continue
                            if v.getAddress() is not None and \
                                    v.getAddress().isMemoryAddress() and \
                                    v.getAddress().getOffset() == TARGET:
                                C.append(
                                    (op.getSeqnum().getTarget().getOffset(),
                                     fn.getName()))
                                break
            except Exception:
                continue
        print("   decompiled OK: %d" % ndec)
        Cset = sorted(set(a for a, _ in C))
        print("   method C store sites: %d" % len(Cset))
        for a in Cset:
            print("      0x%06X" % a)

        # ------------------------------------------------------------------
        print()
        print("=" * 78)
        print("PHASE 3  METHOD D -- WHOLE-LISTING LINEAR SWEEP (sees unswept)")
        print("=" * 78)
        D = []
        regs = {}
        it = listing.getInstructions(True)
        prev_end = None
        ninstr = 0
        while it.hasNext():
            ins = it.next()
            ninstr += 1
            off = ins.getAddress().getOffset()
            # reset register state whenever there is an address discontinuity
            # (new block) -- conservative, never leaks across a gap
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
                    regs[d0] = (int(ins.getScalar(1).getValue()) << 16) \
                        & 0xFFFFFFFF
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("e_add16i", "e_addi", "addi", "e_add2i.", "se_addi"):
                try:
                    src = ins.getDefaultOperandRepresentation(1).strip().lower()
                    val = int(ins.getScalar(2).getValue())
                    if src in regs:
                        regs[d0] = (regs[src] + val) & 0xFFFFFFFF
                    else:
                        regs.pop(d0, None)
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
            elif mn.startswith(STORE_MN):
                try:
                    t = ins.getDefaultOperandRepresentation(1).strip().lower()
                except Exception:
                    t = ""
                disp, reg = parse_disp(t)
                if reg in regs and disp is not None:
                    if ((regs[reg] + disp) & 0xFFFFFFFF) == TARGET:
                        fnc = fm.getFunctionContaining(ins.getAddress())
                        D.append((off, str(ins),
                                  fnc.getName() if fnc else "UNSWEPT"))
            elif d0 in regs and not mn.startswith(CMP_MN + STORE_MN):
                regs.pop(d0, None)
        print("   swept %d instructions in the whole listing" % ninstr)
        print("   method D store sites: %d" % len(D))
        for off, txt, f in D:
            print("      0x%06X  %-28s %s" % (off, txt, f))

        # ------------------------------------------------------------------
        print()
        print("=" * 78)
        print("UNION / COMPARISON")
        print("=" * 78)
        Dset = set(o for o, _, _ in D)
        allsites = sorted(set(KNOWN) | set(Cset) | Dset)
        print("   %-10s %-8s %-8s %-8s" % ("site", "311(6)", "C(pcode)", "D(lin)"))
        for a in allsites:
            print("   0x%06X   %-8s %-8s %-8s"
                  % (a, "Y" if a in KNOWN else ".",
                     "Y" if a in Cset else ".",
                     "Y" if a in Dset else "."))
        print("\n   UNION SIZE = %d" % len(allsites))
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
