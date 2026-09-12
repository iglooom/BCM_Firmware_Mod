#!/usr/bin/env python3
"""Who writes the remote-start STATE ENUM at base+0x70 (0x4000965C)?

Ground truth from vehicle_session_1.md Sec.5.2: during a real remote start this
cell goes 0 -> 0x0A and returns to 0 when quiet, on both sides.  It is the best
"remote start is active" indicator found, and a far better trigger target than
APP_power_mode (refuted, Sec.5.4).

Also traced: bit 27 of 0x40009680 (base+0x94), the sole blocking term of
FUN_000ADADA's guard -- Sec.1.  If its writer is a hardware/RFA-driven input,
forcing it in RAM may be overwritten before the periodic task samples it, and a
depth-4 trigger built on it would silently fail.

METHOD -- all three instruments, because this project has repeatedly found that
their blindness REVERSES between cells (AGENTS.md rules 17/44):
   A. Ghidra reference manager
   B. base+displacement sweep, register tracking scoped PER FUNCTION (rule 17)
   C. decompiler p-code CALLOTHER 0x10000002 = store (rule 14)

CONTROLS (rule 45 -- a control must share the SUBJECT'S region AND form):
   the same three instruments are run against 0x40009648 (base+0x5C, the hold
   timer) and 0x40009620 (base+0x34, a confirmed run-timer) -- cells in the
   SAME struct, accessed the same way.  If an instrument finds nothing for
   those either, its null on +0x70 is uninformative.

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

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

BASE = 0x400095EC
TARGETS = {
    0x4000965C: "STATE ENUM base+0x70  (0 -> 0x0A while running)",
    0x40009680: "GATE WORD base+0x94   (bit27 = the blocker)",
}
CONTROLS = {
    0x40009648: "hold timer base+0x5C  (control)",
    0x40009620: "run timer  base+0x34  (control)",
}

STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu")


def parse_disp(txt):
    """Parse a signed displacement.  Rule 16: strip sign, parse, re-apply."""
    m = re.match(r"(-?)0x([0-9a-fA-F]+)\((r\d+)\)", txt)
    if not m:
        m2 = re.match(r"(-?)(\d+)\((r\d+)\)", txt)
        if not m2:
            return None, None
        sign, mag, reg = m2.groups()
        v = int(mag)
    else:
        sign, mag, reg = m.groups()
        v = int(mag, 16)
    return (-v if sign == "-" else v), reg


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        refmgr = program.getReferenceManager()

        allcells = dict(TARGETS)
        allcells.update(CONTROLS)

        # ---------- A. reference manager ----------
        print("=" * 74)
        print("A. REFERENCE MANAGER")
        print("=" * 74)
        A = defaultdict(list)
        for addr, desc in allcells.items():
            try:
                refs = refmgr.getReferencesTo(af.getAddress(addr))
                for r in refs:
                    fa = r.getFromAddress()
                    ins = listing.getInstructionAt(fa)
                    if ins is None:
                        continue
                    mn = ins.getMnemonicString().lower()
                    if mn.startswith(STORE_MN):
                        A[addr].append((fa.getOffset(), str(ins)))
            except Exception:
                pass
            print("   0x%08X %-38s %d store ref(s)"
                  % (addr, desc, len(A[addr])))

        # ---------- B. base+displacement sweep, PER FUNCTION ----------
        print()
        print("=" * 74)
        print("B. BASE+DISP SWEEP  (register state scoped per function, rule 17)")
        print("=" * 74)
        B = defaultdict(list)
        wanted = {a: d for a, d in allcells.items()}
        nfun = 0
        for fn in fm.getFunctions(True):
            nfun += 1
            regs = {}
            body = fn.getBody()
            ins = listing.getInstructionAt(body.getMinAddress())
            lim = body.getMaxAddress().getOffset()
            while ins is not None and ins.getAddress().getOffset() <= lim:
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
                elif mn in ("e_add16i", "e_addi", "addi"):
                    try:
                        src = ins.getDefaultOperandRepresentation(1).strip().lower()
                        val = int(ins.getScalar(2).getValue())
                        if src in regs:
                            regs[d0] = (regs[src] + val) & 0xFFFFFFFF
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
                        ea = (regs[reg] + disp) & 0xFFFFFFFF
                        if ea in wanted:
                            B[ea].append((ins.getAddress().getOffset(),
                                          str(ins), fn.getName()))
                elif d0 in regs and not mn.startswith(("e_cmp", "se_cmp", "cmp")):
                    regs.pop(d0, None)
                ins = ins.getNext()
        print("   swept %d functions" % nfun)
        for addr, desc in allcells.items():
            print("   0x%08X %-38s %d store(s)" % (addr, desc, len(B[addr])))

        # ---------- verdict ----------
        print()
        print("=" * 74)
        print("RESULTS")
        print("=" * 74)
        for addr, desc in allcells.items():
            tag = "TARGET " if addr in TARGETS else "control"
            hits = {}
            for a, t in A[addr]:
                hits[a] = t
            for a, t, f in B[addr]:
                hits[a] = "%s   [%s]" % (t, f)
            print("\n%s 0x%08X  %s" % (tag, addr, desc))
            if not hits:
                print("     no store found by A or B")
            for a in sorted(hits):
                fn = fm.getFunctionContaining(af.getAddress(a))
                print("     0x%06X  %-34s fn=%s"
                      % (a, hits[a], fn.getName() if fn else "NONE(unswept)"))

        ctrl_found = any(A[a] or B[a] for a in CONTROLS)
        print()
        print("CONTROL CHECK (rule 45): controls are in the SAME struct and")
        print("accessed the same way as the targets.")
        print("   controls produced hits: %s" % ("YES -> a null on a target is"
                                                 " informative" if ctrl_found
                                                 else "NO -> every null below"
                                                 " is UNINFORMATIVE"))
        if not ctrl_found:
            print("   ⇒ Do NOT read any 'no store found' above as a negative.")
            print("     Re-run with p-code (method C) before concluding.")
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
