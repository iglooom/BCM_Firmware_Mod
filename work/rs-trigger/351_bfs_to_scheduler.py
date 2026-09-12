#!/usr/bin/env python3
"""351 - full backward reachability climb from FUN_000ADADA to a scheduler.

350 stopped at 0x0AD73E ("JUMP-ONLY from 0x0AD71E") because it followed a single
linear chain.  This script does a proper BREADTH-FIRST backward closure over all
three edge kinds (CALL, JUMP, byte-adjacency FALLTHROUGH) until it reaches a
node that is a direct callee of APP_feature_periodic 0x062848, or exhausts.

CONTROLS
  C1 (reachability instrument works): the same closure started at 0x0AEEC6 must
     reach 0x062848.  Already PASSed in 350; re-asserted here inside the BFS so
     the BFS itself -- not just the single-step climb -- is certified.
  C2 (unrelated-site control, rule 23): the same closure started at a function
     picked from a DIFFERENT feature region, 0x0007890A (a documented
     APP_feature_periodic callee), must also reach 0x062848 -- proving the
     closure is not tuned to the 0x0AExxx region.
  C3 (non-vacuity): the closure must NOT reach 0x062848 from an address chosen
     to be unrelated -- the Volcano codec leaf VOL_sig_get16 0x0FBB38 is called
     from everywhere, so it is a poor negative; instead use the PBL entry region
     0x000200 which is not part of the application periodic spine.
     A "reaches everything" result would mean the closure is vacuous.

READ-ONLY.
"""
import os, sys, json, traceback
from collections import deque

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
OUT = os.path.join(REPO, "work/rs-trigger/logs")

PERIODIC = 0x062848
SUBJECT = 0x0ADADA
C1_SITE = 0x0AEEC6
C2_SITE = 0x07890A
C3_SITE = 0x000200

project = None
try:
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject

    project = GhidraProject.openProject(PROJ, NAME, True)
    prog = project.openProgram("/", PROG, True)
    af = prog.getAddressFactory().getDefaultAddressSpace()
    listing = prog.getListing()
    fm = prog.getFunctionManager()
    rm = prog.getReferenceManager()

    def preds(a):
        """All backward edges into address a: CALL, JUMP, FALLTHROUGH."""
        out = []
        ad = af.getAddress(a)
        for r in rm.getReferencesTo(ad):
            rt = r.getReferenceType()
            if rt.isCall() or rt.isJump():
                fa = r.getFromAddress()
                f = fm.getFunctionContaining(fa)
                anchor = f.getEntryPoint().getOffset() if f else fa.getOffset()
                out.append((anchor, "CALL" if rt.isCall() else "JUMP",
                            fa.getOffset()))
        prev = listing.getInstructionBefore(ad)
        if prev is not None:
            ft = prev.getFallThrough()
            if ft is not None and ft.getOffset() == a:
                f = fm.getFunctionContaining(prev.getAddress())
                anchor = f.getEntryPoint().getOffset() if f else prev.getAddress().getOffset()
                out.append((anchor, "FALLTHROUGH", prev.getAddress().getOffset()))
        return out

    def bfs(start, target, cap=4000):
        seen = {start: None}
        q = deque([start])
        n = 0
        while q and n < cap:
            cur = q.popleft(); n += 1
            if cur == target:
                # rebuild path
                path = []
                x = cur
                while x is not None:
                    path.append(x)
                    x = seen[x][0] if seen[x] else None
                return list(reversed(path)), seen, n
            for anchor, kind, site in preds(cur):
                if anchor not in seen:
                    seen[anchor] = (cur, kind, site)
                    q.append(anchor)
        return None, seen, n

    def show(label, start):
        path, seen, n = bfs(start, PERIODIC)
        print("=" * 70)
        print("%s: BFS from 0x%06X, visited %d nodes" % (label, start, n))
        if path:
            print("  REACHES APP_feature_periodic.  Shortest edge path (target->start):")
            # seen[] holds successor direction; rebuild readable chain
            chain = []
            x = PERIODIC
            while x != start and x in seen and seen[x]:
                succ, kind, site = seen[x]
                chain.append("0x%06X --%s@0x%06X--> 0x%06X" % (x, kind, site, succ))
                x = succ
            for c in reversed(chain):
                print("    ", c)
        else:
            print("  DOES NOT REACH APP_feature_periodic within cap")
        return path is not None, len(seen)

    okC1, _ = show("C1 control (0x0AEEC6)", C1_SITE)
    okC2, _ = show("C2 unrelated-site control (0x07890A)", C2_SITE)
    okC3, n3 = show("C3 non-vacuity probe (0x000200)", C3_SITE)
    okS, nS = show("SUBJECT FUN_000ADADA", SUBJECT)

    print()
    print("CONTROLS: C1=%s C2=%s C3(should be NOT-reached)=%s"
          % ("PASS" if okC1 else "FAIL",
             "PASS" if okC2 else "FAIL",
             "PASS" if not okC3 else "FAIL(vacuous)"))
    print("SUBJECT reaches periodic spine: %s" % okS)

    json.dump({"C1": okC1, "C2": okC2, "C3_reached": okC3, "subject": okS},
              open(os.path.join(OUT, "351_bfs.json"), "w"), indent=1)

except Exception:
    traceback.print_exc()
    sys.stdout.flush(); sys.stderr.flush()
finally:
    try:
        if project is not None:
            project.close()
    except Exception:
        traceback.print_exc()
    sys.stdout.flush(); sys.stderr.flush()
    os._exit(0)
