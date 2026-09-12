#!/usr/bin/env python3
"""350 - climb the sweep-split fallthrough chain from FUN_000ADADA upward until
a block with a real CALL reference is reached, and identify its scheduler.

Rationale (AGENTS rule 19): this image's linear sweep splits one logical routine
into dozens of zero-caller FUN_ blocks.  getCallingFunctions() reports "no
callers" for every one of them.  The only correct climb walks
  (i) CALL/JUMP references from the reference manager, and
  (ii) byte-adjacency FALLTHROUGH,
and stops when a block is reached by a genuine CALL.

CONTROL: applying the same climb to 0x0AEEC6 -- a block already PROVEN to be a
direct callee of APP_feature_periodic 0x062848 -- must terminate at 0x062848 in
one hop.  Same region (0x0AExxx), same addressing form.  A failure makes every
other result of this script INCONCLUSIVE.

Also emits every store instruction in the climbed body with its resolved
absolute target, so the report can list "RAM cells the path writes" from the
listing rather than from the decompiler.

READ-ONLY.
"""
import os, sys, json, traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
OUT = os.path.join(REPO, "work/rs-trigger/logs")

SUBJECTS = [0x0ADADA, 0x0AEEC6]
STORE_RANGES = [(0x0AD970, 0x0ADE12),      # the 0xAD9xx..0xADDxx routine
                (0x0AEEC6, 0x0AEF60)]      # FUN_000aeec6 head

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

    def climb(start, limit=60):
        chain = []
        cur = start
        seen = set()
        while cur not in seen and len(chain) < limit:
            seen.add(cur)
            ad = af.getAddress(cur)
            calls = []
            for r in rm.getReferencesTo(ad):
                rt = r.getReferenceType()
                if rt.isCall():
                    fa = r.getFromAddress()
                    f = fm.getFunctionContaining(fa)
                    calls.append(("CALL", fa.getOffset(),
                                  f.getName() if f else None,
                                  f.getEntryPoint().getOffset() if f else None))
            if calls:
                chain.append({"block": "%06X" % cur, "reached_by": "CALL",
                              "callers": [{"from": "%06X" % c[1], "func": c[2],
                                           "entry": "%06X" % c[3] if c[3] is not None else None}
                                          for c in calls]})
                return chain
            prev = listing.getInstructionBefore(ad)
            if prev is None:
                chain.append({"block": "%06X" % cur, "reached_by": "DEAD-END"})
                return chain
            ft = prev.getFallThrough()
            if ft is not None and ft.getOffset() == cur:
                pf = fm.getFunctionContaining(prev.getAddress())
                nxt = pf.getEntryPoint().getOffset() if pf else prev.getAddress().getOffset()
                chain.append({"block": "%06X" % cur, "reached_by": "FALLTHROUGH",
                              "from": "%06X" % prev.getAddress().getOffset(),
                              "prev_func": pf.getName() if pf else None,
                              "prev_entry": "%06X" % nxt})
                cur = nxt
            else:
                # jump-only predecessors
                jumps = []
                for r in rm.getReferencesTo(ad):
                    if r.getReferenceType().isJump():
                        jumps.append(r.getFromAddress().getOffset())
                chain.append({"block": "%06X" % cur, "reached_by": "JUMP-ONLY",
                              "jumps_from": ["%06X" % j for j in sorted(jumps)]})
                return chain
        return chain

    results = {}
    for s in SUBJECTS:
        print("=" * 70)
        print("CLIMB from 0x%06X" % s)
        ch = climb(s)
        results["%06X" % s] = ch
        for step in ch:
            print("  ", json.dumps(step))

    ctl = results["0AEEC6"]
    C1 = (ctl and ctl[-1].get("reached_by") == "CALL"
          and any(c["entry"] == "062848" for c in ctl[-1]["callers"]))
    print("\nCONTROL (climb from 0x0AEEC6 terminates at APP_feature_periodic 062848):",
          "PASS" if C1 else "FAIL -> results INCONCLUSIVE")

    print()
    print("###### STORES with resolved absolute targets ######")
    stores = []
    for lo, hi in STORE_RANGES:
        print("--- %06X..%06X ---" % (lo, hi))
        for ins in listing.getInstructions(af.getAddress(lo), True):
            off = ins.getAddress().getOffset()
            if off >= hi:
                break
            m = ins.getMnemonicString()
            if not (m.startswith("se_st") or m.startswith("e_st") or m.startswith("st")):
                continue
            tgts = [(str(r.getToAddress()), str(r.getReferenceType()))
                    for r in ins.getReferencesFrom() if r.getReferenceType().isWrite()]
            rec = {"site": "%06X" % off, "insn": str(ins),
                   "targets": [t[0] for t in tgts]}
            stores.append(rec)
            print("  %06X  %-32s -> %s" % (off, ins, ",".join(t[0] for t in tgts) or "UNRESOLVED"))

    json.dump({"climbs": results, "control": C1, "stores": stores},
              open(os.path.join(OUT, "350_climb.json"), "w"), indent=1)
    print("\nWROTE 350_climb.json")

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
