#!/usr/bin/env python3
"""348 - exact stores + caller chain for the RX->consumer path.

(a) Raw disassembly of APP_rke_code_commit 0x058538 -- prove the valid flag is
    written 0xFF (a LITERAL), not 1.
(b) Raw disassembly of the FUN_000ad97c bit-27 arm 0x0ADA00..0x0ADA90 with
    resolved store targets.
(c) Caller climb for 0x058538 / 0x0584A4 / 0x0AEEC6 / 0x0AD97C / 0x0ADADA using
    getReferencesTo accepting CALL + JUMP + byte-adjacency fallthrough
    (AGENTS rule 19 -- getCallingFunctions() is structurally blind here).
(d) All WRITE references to the RAM cells of interest, so the report can state
    which cells the RX path is the sole writer of.

CONTROL for (c): 0x0AEEC6 is a DOCUMENTED direct callee of APP_feature_periodic
0x062848 (docs/rke_chain_code.json).  The climb must recover 0x062848 for it.
A failure => the climb is INCONCLUSIVE for every other node.

READ-ONLY.
"""
import os, sys, json, traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
OUT = os.path.join(REPO, "work/rs-trigger/logs")

CLIMB = [0x058538, 0x0584A4, 0x0AEEC6, 0x0AD97C, 0x0ADADA]
CELLS = [0x40003F53, 0x40002DA2, 0x400095E1, 0x4000968B,
         0x4000967C, 0x40009680, 0x40009672, 0x400004FE,
         0x4000091E, 0x4000091F]
DIS = [(0x058538, 0x0585C0), (0x0ADA00, 0x0ADA98), (0x0584A4, 0x0584D0)]

project = None
try:
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.symbol import RefType

    project = GhidraProject.openProject(PROJ, NAME, True)
    prog = project.openProgram("/", PROG, True)
    af = prog.getAddressFactory().getDefaultAddressSpace()
    listing = prog.getListing()
    fm = prog.getFunctionManager()
    rm = prog.getReferenceManager()

    print("###### (a)/(b) DISASSEMBLY ######")
    for lo, hi in DIS:
        print("--- %06X..%06X ---" % (lo, hi))
        for ins in listing.getInstructions(af.getAddress(lo), True):
            off = ins.getAddress().getOffset()
            if off >= hi:
                break
            refs = [str(r.getToAddress()) + ":" + str(r.getReferenceType())
                    for r in ins.getReferencesFrom()]
            print("  %06X  %-34s %s" % (off, ins, " ".join(refs)))

    print()
    print("###### (c) CALLER CLIMB (CALL+JUMP+fallthrough) ######")
    climb = {}
    for t in CLIMB:
        ad = af.getAddress(t)
        callers = []
        for r in rm.getReferencesTo(ad):
            rt = r.getReferenceType()
            if rt.isCall() or rt.isJump():
                fa = r.getFromAddress()
                f = fm.getFunctionContaining(fa)
                callers.append({"from": str(fa),
                                "type": str(rt),
                                "in_func": f.getName() if f else None,
                                "entry": str(f.getEntryPoint()) if f else None})
        # fallthrough predecessor
        prev = listing.getInstructionBefore(ad)
        ft = None
        if prev is not None and prev.getFallThrough() is not None \
                and prev.getFallThrough().getOffset() == t:
            pf = fm.getFunctionContaining(prev.getAddress())
            ft = {"from": str(prev.getAddress()), "type": "FALLTHROUGH",
                  "in_func": pf.getName() if pf else None,
                  "entry": str(pf.getEntryPoint()) if pf else None}
        climb["%06X" % t] = {"refs": callers, "fallthrough": ft}
        print("0x%06X : %d CALL/JUMP refs, fallthrough=%s"
              % (t, len(callers), ft["from"] if ft else None))
        for c in callers:
            print("    <- %s %s  %s@%s" % (c["from"], c["type"], c["in_func"], c["entry"]))
        if ft:
            print("    <- %s FALLTHROUGH  %s@%s" % (ft["from"], ft["in_func"], ft["entry"]))

    ctl = any(c["entry"] == "00062848" for c in climb["0AEEC6"]["refs"])
    print("\nCONTROL (0x0AEEC6 called from APP_feature_periodic 0x062848): %s"
          % ("PASS" if ctl else "FAIL -> climb INCONCLUSIVE"))

    print()
    print("###### (d) WRITE refs to the path's RAM cells ######")
    cellrefs = {}
    for c in CELLS:
        ad = af.getAddress(c)
        ws, rs = [], []
        for r in rm.getReferencesTo(ad):
            rt = r.getReferenceType()
            fa = str(r.getFromAddress())
            if rt.isWrite():
                ws.append(fa)
            elif rt.isRead():
                rs.append(fa)
        cellrefs["0x%08X" % c] = {"writes": sorted(ws), "reads": sorted(rs)}
        print("0x%08X : %2d writes %s | %d reads"
              % (c, len(ws), sorted(ws)[:8], len(rs)))

    json.dump({"climb": climb, "cellrefs": cellrefs, "control_climb": ctl},
              open(os.path.join(OUT, "348_path.json"), "w"), indent=1)
    print("\nWROTE 348_path.json")

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
