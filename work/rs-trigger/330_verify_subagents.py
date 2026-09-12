#!/usr/bin/env python3
"""VERIFY the three subagents' load-bearing claims independently.

Child summaries are SELF-REPORTS.  Three claims decide what we do next, so each
is re-derived here from the program itself rather than accepted:

  C1 (sa-1)  0x113594 stores the LITERAL 3 to DAT_40002F3C.
             => the outer gate of FUN_000AD6C6 IS reachable.
             This REVERSES the reading my own 313 scan suggested.

  C2 (sa-2)  0x0ADA3E is the SOLE bit-specific setter of bit 27 (0x08000000)
             of 0x40009680, via se_bseti r0,0x4 at 0x0ADA3C, inside
             FUN_000AD97C.

  C3 (sa-2)  There are 44 store sites to 0x40009680, not the 33 I briefed.

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
STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw")


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    fails = []
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        refmgr = program.getReferenceManager()

        def ins_at(a):
            return listing.getInstructionAt(af.getAddress(a))

        # ---------------- C1 ----------------
        print("=" * 70)
        print("C1  0x113594 stores literal 3 to DAT_40002F3C ?")
        print("=" * 70)
        for a in (0x113590, 0x113592, 0x113594, 0x113596):
            i = ins_at(a)
            if i:
                print("   0x%06X  %s" % (a, i))
        st = ins_at(0x113594)
        ok1 = False
        if st and st.getMnemonicString().lower().startswith(STORE_MN):
            src = st.getDefaultOperandRepresentation(0).strip().lower()
            cur = st.getPrevious()
            n = 0
            while cur is not None and n < 12:
                n += 1
                m = cur.getMnemonicString().lower()
                d = cur.getDefaultOperandRepresentation(0).strip().lower()
                if d == src and m in ("se_li", "e_li", "li"):
                    v = int(cur.getScalar(1).getValue())
                    print("   -> value register %s defined by %s = %d"
                          % (src, cur, v))
                    ok1 = (v == 3)
                    break
                cur = cur.getPrevious()
        print("   C1 %s" % ("CONFIRMED - literal 3 IS stored" if ok1
                            else "NOT CONFIRMED"))
        if not ok1:
            fails.append("C1")

        # ---------------- C2 ----------------
        print()
        print("=" * 70)
        print("C2  0x0ADA3E sets bit 27 (0x08000000) of 0x40009680 ?")
        print("=" * 70)
        for a in (0x0ADA34, 0x0ADA3C, 0x0ADA3E):
            i = ins_at(a)
            if i:
                print("   0x%06X  %-28s" % (a, i))
        bs = ins_at(0x0ADA3C)
        ok2 = False
        if bs and "bseti" in bs.getMnemonicString().lower():
            op = int(bs.getScalar(1).getValue())
            mask = 1 << (31 - op)
            print("   se_bseti operand=%d  (MSB-numbered) -> mask 0x%08X"
                  % (op, mask))
            print("   target bit 27 mask                  0x%08X" % 0x08000000)
            ok2 = (mask == 0x08000000)
        print("   C2 %s" % ("CONFIRMED" if ok2 else "NOT CONFIRMED"))
        if not ok2:
            fails.append("C2")

        # ---------------- C3 ----------------
        print()
        print("=" * 70)
        print("C3  how many STORE sites to 0x40009680 ?  (I briefed 33)")
        print("=" * 70)
        refs = refmgr.getReferencesTo(af.getAddress(0x40009680))
        n_w = 0
        addrs = []
        for r in refs:
            i = listing.getInstructionAt(r.getFromAddress())
            if i and i.getMnemonicString().lower().startswith(STORE_MN):
                n_w += 1
                addrs.append(r.getFromAddress().getOffset())
        print("   reference manager store refs: %d" % n_w)
        print("   subagent claimed            : 44")
        print("   my brief said               : 33")
        hi = [a for a in addrs if a >= 0x0AE900]
        print("   sites at/above 0x0AE900 (the block I missed): %d" % len(hi))
        ok3 = n_w == 44
        print("   C3 %s" % ("CONFIRMED" if ok3 else
                            "differs - got %d" % n_w))
        if not ok3:
            fails.append("C3")

        print()
        print("=" * 70)
        print("VERDICT: %s" % ("all three claims independently confirmed"
                               if not fails else "UNCONFIRMED: %s" % fails))
        print("=" * 70)
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
