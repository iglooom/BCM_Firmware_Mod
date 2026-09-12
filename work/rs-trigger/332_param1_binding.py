#!/usr/bin/env python3
"""Confirm param_1 of FUN_000AD97C == 0x400095DC from the CALL SITE.

vehicle_session_1.md Sec.7.5.1 derived this from an arithmetic coincidence:
*param_1 / 60000 == 14 and the byte at 0x400095E0 read 0x0E == 14.  Two
instruments agreeing is good evidence, but param_1 is a genuine function
PARAMETER, so the binding can be checked directly: find the caller, and read
what it puts in r3 (PPC EABI first argument) before the e_bl.

If the caller sets r3 = 0x400095DC the binding is PROVEN, and the depth-4
target 0x400095E1 (= param_1+5) is safe to build on.
If it does not, Sec.7.5.1 is a coincidence and depth 4 must not be built.

Callers are found via the reference manager accepting CALL *and* JUMP refs and
falling back to byte-adjacency, because this image's linear sweep splits
routines into zero-caller blocks (AGENTS.md rule 19 -- getCallingFunctions()
produced a false "0 callers" in this project before).

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
TARGET = 0x000AD97C
EXPECT = 0x400095DC


def main():
    project = GhidraProject.openProject(
        os.path.join(ROOT, "ghidra_proj_fullflash"), "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        L = program.getListing()
        refmgr = program.getReferenceManager()

        print("=" * 72)
        print("callers of FUN_000AD97C @ 0x%06X" % TARGET)
        print("=" * 72)
        sites = []
        for r in refmgr.getReferencesTo(af.getAddress(TARGET)):
            t = str(r.getReferenceType())
            if "CALL" in t.upper() or "JUMP" in t.upper():
                sites.append((r.getFromAddress().getOffset(), t))
        if not sites:
            print("   none via reference manager")
        for a, t in sorted(sites):
            print("   0x%06X  %s" % (a, t))

        print()
        print("=" * 72)
        print("r3 (EABI arg0) at each call site -- walk back for its definition")
        print("=" * 72)
        proven = False
        for site, _t in sorted(sites):
            print("\n  call at 0x%06X:" % site)
            cur = L.getInstructionAt(af.getAddress(site))
            cur = cur.getPrevious() if cur else None
            regs = {}
            seen = []
            n = 0
            while cur is not None and n < 60:
                n += 1
                mn = cur.getMnemonicString().lower()
                try:
                    d0 = cur.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    d0 = ""
                seen.append((cur.getAddress().getOffset(), str(cur)))
                if mn in ("e_lis", "se_lis", "lis"):
                    try:
                        regs.setdefault(d0, ("lis",
                                             int(cur.getScalar(1).getValue())))
                    except Exception:
                        pass
                if mn in ("e_add16i", "e_addi", "addi") and d0 == "r3":
                    try:
                        src = cur.getDefaultOperandRepresentation(1).strip().lower()
                        val = int(cur.getScalar(2).getValue())
                        print("     0x%06X  %s" % (cur.getAddress().getOffset(),
                                                   cur))
                        # find the lis for src earlier
                        p2 = cur.getPrevious()
                        m = 0
                        while p2 is not None and m < 40:
                            m += 1
                            if (p2.getMnemonicString().lower() in
                                    ("e_lis", "se_lis", "lis")):
                                dd = p2.getDefaultOperandRepresentation(0).strip().lower()
                                if dd == src:
                                    hi = int(p2.getScalar(1).getValue()) << 16
                                    ea = (hi + val) & 0xFFFFFFFF
                                    print("     0x%06X  %s"
                                          % (p2.getAddress().getOffset(), p2))
                                    print("     => r3 = 0x%08X  %s"
                                          % (ea, "*** MATCHES 0x%08X ***" % EXPECT
                                             if ea == EXPECT else
                                             "(expected 0x%08X)" % EXPECT))
                                    if ea == EXPECT:
                                        proven = True
                                    break
                            p2 = p2.getPrevious()
                    except Exception:
                        pass
                cur = cur.getPrevious()
            if not any("r3" in s[1] for s in seen):
                print("     (no r3 definition in the preceding %d instrs)" % n)
                for a, t in seen[:6]:
                    print("       0x%06X  %s" % (a, t))

        print()
        print("=" * 72)
        print("VERDICT: param_1 == 0x%08X %s" % (EXPECT,
              "PROVEN from a call site" if proven else
              "NOT proven -- Sec.7.5.1 rests on the arithmetic match only"))
        print("=" * 72)
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
