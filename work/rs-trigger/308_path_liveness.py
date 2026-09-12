#!/usr/bin/env python3
"""PATH-SENSITIVE register check -- 307 was linear, and that is not sufficient.

THE GAP
  307_reg_safety.py swept FUN_0010B65E linearly and asked "is r5 used after
  the hook?".  But the cave does not fall through the function linearly: it
  has TWO exits, and they land in different places.

      not-our-DID  -> RET  = 0x0010B768   (stock compare path)
      handled      -> CONT = 0x0010B992   ("DID handled, continue")

  A linear sweep mixes both paths together, so a register that is dead on one
  path and LIVE on the other can be reported SAFE.  That is the same
  scope/coverage error as AGENTS.md rules 17/18/45 -- the instrument worked,
  the question it answered was the wrong one.

  It matters specifically for r5: peek's cave (already proven on the bench)
  clobbers r3/r4/r9 and branches to the same CONT, so those are empirically
  fine.  **r5 is NEW in the rs cave** and has no such empirical cover.

METHOD
  Walk forward from each exit point separately, following fallthrough and
  taken branches within the function, and record for each watched register
  whether its first occurrence is a USE (live -> unsafe) or a DEFINITION
  (dead -> safe).

CONTROL (rule 9): r26/r27/r28 are known live at CONT (the loop continues with
  them).  They must come back LIVE on the CONT path.  If they do not, this
  walker cannot detect liveness and any SAFE verdict is vacuous.

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
RET = 0x0010B768
CONT = 0x0010B992
FN_LO, FN_HI = 0x0010B65E, 0x0010BA83

WATCH = ["r3", "r4", "r5"]
CONTROL = ["r26", "r27", "r28"]

NON_DEFINING = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
                "e_cmp", "se_cmp", "cmp", "e_cmpl", "e_cmpli", "e_cmpl16i",
                "e_cmph", "e_bc", "e_b", "se_b", "e_bl", "se_bl")


def main():
    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", True)
    program = project.openProgram("/", "flash_merged.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()

        def walk(start, regs, limit=400):
            """Forward walk; returns {reg: ('USE'|'DEF'|None, addr)}."""
            verdict = {r: (None, None) for r in regs}
            seen = set()
            stack = [start]
            steps = 0
            order = []
            while stack and steps < limit:
                a = stack.pop(0)
                if a in seen or not (FN_LO <= a <= FN_HI):
                    continue
                seen.add(a)
                steps += 1
                ins = listing.getInstructionAt(af.getAddress(a))
                if ins is None:
                    continue
                order.append(a)
                mn = ins.getMnemonicString().lower()
                for i in range(ins.getNumOperands()):
                    txt = ins.getDefaultOperandRepresentation(i).strip().lower()
                    for r in regs:
                        if verdict[r][0] is not None:
                            continue
                        hit = (r == txt or ("(%s)" % r) in txt
                               or txt.startswith(r + ","))
                        if not hit:
                            continue
                        if i == 0 and not mn.startswith(NON_DEFINING):
                            verdict[r] = ("DEF", a)
                        else:
                            verdict[r] = ("USE", a)
                # successors: fallthrough + branch target
                nxt = ins.getNext()
                if ins.getFallThrough() is not None:
                    stack.append(ins.getFallThrough().getOffset())
                elif nxt is not None and not mn.startswith(("e_b", "se_b")):
                    stack.append(nxt.getAddress().getOffset())
                for ref in ins.getFlows():
                    stack.append(ref.getOffset())
            return verdict, steps

        print("=" * 72)
        print("PATH-SENSITIVE liveness from each cave exit")
        print("=" * 72)

        for name, start in (("RET  (not-our-DID)", RET),
                            ("CONT (handled)", CONT)):
            print("\n### %s -> 0x%06X" % (name, start))
            v, steps = walk(start, WATCH + CONTROL)
            print("   explored %d blocks" % steps)
            ctrl_live = [r for r in CONTROL if v[r][0] == "USE"]
            print("   CONTROL live-at-entry: %s  -> %s"
                  % (", ".join(ctrl_live) if ctrl_live else "NONE",
                     "PASS" if ctrl_live else "FAIL (walker cannot see liveness)"))
            for r in WATCH:
                kind, a = v[r]
                if kind == "USE":
                    tag = "*** LIVE at 0x%06X -- UNSAFE TO CLOBBER ***" % a
                elif kind == "DEF":
                    tag = "SAFE (redefined at 0x%06X before any use)" % a
                else:
                    tag = "SAFE (never referenced on this path)"
                print("   %-4s %s" % (r, tag))

        print()
        print("=" * 72)
        print("NOTE: peek's cave already clobbers r3/r4/r9 and exits via the")
        print("same two points, and is proven working on bench #1 -- so those")
        print("carry empirical cover.  r5 is NEW and does not.")
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
