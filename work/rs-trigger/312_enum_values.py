#!/usr/bin/env python3
"""What VALUE does each writer of the state enum (0x4000965C) store?

311 found 6 writers; the decompiles show only `= 0` (reset paths) and NO
literal 0x0A anywhere.  So the 0x0A observed on the vehicle
(vehicle_session_1.md Sec.5.2) is a COMPUTED value.  This walks back from each
store to the instruction that defines the stored register.

Method note (AGENTS.md rule 16/287): for a STORE, operand 0 is the SOURCE, not
a definition -- a backward walker must not treat it as one, or it halts on the
store itself and reports the store as its own producer.

CONTROL (rule 9): the walker is also run on the two sibling timer cells whose
producers are known to be arithmetic (+0x34, +0x5C).  It must resolve those to
real defining instructions; if it cannot, its output on the enum is vacuous.

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

SITES = {
    0x0AD700: "enum  se_stw r0,0x0(r7)",
    0x0AD738: "enum  e_stw r0,0x70(r31)",
    0x0AD762: "enum  e_stw r6,0x70(r31)",
    0x0AE8D4: "enum  se_stw r0,0x2c(r6)",
    0x0AEB88: "enum  se_stw r7,0x2c(r6)   [UNSWEPT]",
    0x0AEBE0: "enum  se_stw r0,0x2c(r6)",
}
CONTROLS = {
    0x0AD9A8: "ctrl  se_stw r0,0x34(r31)  (run timer)",
    0x0ADA7E: "ctrl  e_stw r0,0x5c(r31)   (hold timer)",
}

NON_DEFINING = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
                "e_stbu", "e_sthu", "e_stwu",
                "e_cmp", "se_cmp", "cmp", "e_cmpl", "e_cmpli", "e_cmpl16i",
                "e_cmph", "e_b", "se_b", "e_bc")


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()

        def walk(site, depth=40):
            ins = listing.getInstructionAt(af.getAddress(site))
            if ins is None:
                return None, "no instruction"
            try:
                src = ins.getDefaultOperandRepresentation(0).strip().lower()
            except Exception:
                return None, "no operand"
            cur = ins.getPrevious()
            n = 0
            while cur is not None and n < depth:
                n += 1
                mn = cur.getMnemonicString().lower()
                try:
                    d0 = cur.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    d0 = ""
                if d0 == src and not mn.startswith(NON_DEFINING):
                    return cur, "%s  @0x%06X (%d back)" % (
                        str(cur), cur.getAddress().getOffset(), n)
                cur = cur.getPrevious()
            return None, "not defined within %d instructions" % depth

        print("=" * 74)
        print("VALUE PRODUCERS for the state enum 0x4000965C")
        print("=" * 74)
        for site, desc in SITES.items():
            ins, txt = walk(site)
            print("\n  0x%06X  %s" % (site, desc))
            print("      <- %s" % txt)
            if ins is not None:
                mn = ins.getMnemonicString().lower()
                if mn in ("se_li", "e_li", "li", "e_lis"):
                    try:
                        v = int(ins.getScalar(1).getValue())
                        flag = "   *** literal %d (0x%X)%s" % (
                            v, v, "  <<< THE 0x0A STATE" if v == 0xA else "")
                        print("     %s" % flag)
                    except Exception:
                        pass

        print()
        print("=" * 74)
        print("CONTROLS -- the walker must resolve these")
        print("=" * 74)
        ok = 0
        for site, desc in CONTROLS.items():
            ins, txt = walk(site)
            if ins is not None:
                ok += 1
            print("  0x%06X  %-38s <- %s" % (site, desc, txt))
        print("\n  control resolved: %d/%d -> %s"
              % (ok, len(CONTROLS),
                 "PASS" if ok else "FAIL -- results above are VACUOUS"))
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
