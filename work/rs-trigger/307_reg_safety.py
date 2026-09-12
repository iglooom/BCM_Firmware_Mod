#!/usr/bin/env python3
"""P4 (MISSING GATE) -- is r5 safe to clobber in the rs cave?

WHY THIS EXISTS
  300_prereq.py's docstring claims a "P4 free scratch RAM" check.  It was
  never implemented, and docs/rs_trigger_design.md Sec.5 asserted that
  301_build_cave.py "re-runs" peek's register check.  It does not.  Both
  claims were wrong, and they hid a real gap:

    peek's cave chose r9 BY MEASUREMENT (AGENTS.md rule 38: count references
    in the enclosing function, do not assume the EABI volatiles are free).
    The rs cave introduces **r5**, which was never in peek's measured set,
    to carry the MAGIC from the depth body into the reply block.

  If r5 holds a live value in the enclosing DID-dispatch function, clobbering
  it corrupts the stock multi-DID loop -- a failure that would look like
  "some tool's DID reads intermittently break", i.e. maximally hard to
  diagnose over CAN.

METHOD (same as peek's r9 selection)
  Disassemble the whole enclosing function and count references to each GPR,
  separating DEFINITIONS (safe -- the function overwrites it anyway before
  use) from USES.  A register that is only ever DEFINED after our hook, or
  never touched at all, is safe.

CONTROL (rule 9 -- the scan must be able to say NO):
  r26/r27/r28 are KNOWN LIVE at the hook (they carry DID, length, index).
  They must come back with high use counts.  If they do not, the scan is
  broken and any "r5 is free" verdict is vacuous.

Read-only.
"""
import os
import sys
import traceback
from collections import defaultdict

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
HOOK = 0x0010B764
# registers the rs cave clobbers
OURS = ["r0", "r1", "r3", "r4", "r5"]
# registers known live at the hook -- the control
CONTROL = ["r26", "r27", "r28"]

NON_DEFINING = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
                "e_cmp", "se_cmp", "cmp", "e_cmpl", "e_cmpli", "e_cmpl16i",
                "e_cmph", "e_bc", "e_b", "se_b")


def main():
    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", True)
    program = project.openProgram("/", "flash_merged.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()

        fn = fm.getFunctionContaining(af.getAddress(HOOK))
        if fn is None:
            print("no function contains the hook -- unswept block (rule 44)")
            print("falling back to a fixed window around the hook")
            lo, hi = HOOK - 0x400, HOOK + 0x400
            fname = "(unswept window)"
        else:
            body = fn.getBody()
            lo = body.getMinAddress().getOffset()
            hi = body.getMaxAddress().getOffset()
            fname = fn.getName()

        print("=" * 72)
        print("enclosing function: %s   0x%06X..0x%06X" % (fname, lo, hi))
        print("hook at 0x%06X" % HOOK)
        print("=" * 72)

        defs = defaultdict(list)
        uses = defaultdict(list)
        ins = listing.getInstructionAt(af.getAddress(lo))
        n = 0
        while ins is not None and ins.getAddress().getOffset() <= hi:
            n += 1
            mn = ins.getMnemonicString().lower()
            a = ins.getAddress().getOffset()
            nops = ins.getNumOperands()
            for i in range(nops):
                txt = ins.getDefaultOperandRepresentation(i).strip().lower()
                for r in set(OURS + CONTROL):
                    # match the register as a whole token
                    if r == txt or ("(%s)" % r) in txt or txt.startswith(r + ","):
                        if i == 0 and not mn.startswith(NON_DEFINING):
                            defs[r].append(a)
                        else:
                            uses[r].append(a)
            ins = ins.getNext()

        print("swept %d instructions\n" % n)

        print("CONTROL -- these are KNOWN LIVE at the hook:")
        ctrl_ok = True
        for r in CONTROL:
            u = len(uses[r])
            print("   %-4s uses=%-4d defs=%-4d %s"
                  % (r, u, len(defs[r]), "" if u else "<-- SUSPICIOUS"))
            ctrl_ok &= u > 0
        print("   -> %s" % ("PASS (scan can detect live registers)" if ctrl_ok
                            else "FAIL -- verdict below is VACUOUS"))

        print("\nREGISTERS THE RS CAVE CLOBBERS:")
        for r in OURS:
            u = [a for a in uses[r] if a > HOOK]
            d = [a for a in defs[r] if a > HOOK]
            first_use = min(u) if u else None
            first_def = min(d) if d else None
            if first_use is None:
                verdict = "SAFE (never used after the hook)"
            elif first_def is not None and first_def < first_use:
                verdict = "SAFE (redefined at 0x%06X before first use)" % first_def
            else:
                verdict = "*** LIVE -- first use 0x%06X ***" % first_use
            print("   %-4s uses_after=%-3d defs_after=%-3d  %s"
                  % (r, len(u), len(d), verdict))

        print("\nNOTE: r1 is the stack pointer -- the cave saves and restores it")
        print("      via its own frame, which is the standard contract, not a clobber.")
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
