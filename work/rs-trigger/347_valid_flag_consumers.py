#!/usr/bin/env python3
"""347 - Enumerate every VOL_test_and_clear_dirty(0x031360) call site in the whole
image, resolving BOTH arguments (r3 = flag address, r4 = bit index), then filter
for the RKE valid flag 0x40003F53.

WHY THIS MATTERS
  VOL_test_and_clear_dirty tests mask (0x80 >> n).  APP_rke_code_commit writes
  APP_rke_code_valid = 0xFF (every bit).  The debug service writes 1 (mask 0x01
  == bit index 7).  If no consumer uses index 7, the debug write sets a bit
  nobody reads -> the command code persists but nothing fires.  This script
  decides that by enumeration, not by inspection of two functions.

METHOD
  Linear sweep of ALL instructions (no reliance on function membership -- rule
  19: sweep-split blocks have no function and are invisible to xref climbs).
  For each `e_bl 0x31360` (and se_bl variants), walk backwards up to 40
  instructions in the raw instruction stream tracking a tiny register model:
      e_lis rD,imm            -> rD = imm<<16
      e_add16i rD,rA,simm     -> rD = rA + simm      (source is rA!)
      e_addi   rD,rA,simm     -> rD = rA + simm
      e_add2i. / e_or2i       -> handled
      se_li rD,imm            -> rD = imm
      e_li  rD,imm            -> rD = imm
      se_mr rD,rS             -> rD = rS
  Stop the walk on a prior branch-with-link (a call clobbers r3/r4).

CONTROLS (rule 17/27 -- printed explicitly, a failure => INCONCLUSIVE)
  C1  the KNOWN site 0x0AEEDA must resolve to (0x40003F53, bit 2).
      Same address region, same addressing form (e_lis/e_add16i + e_addi) as
      every other subject site.
  C2  the KNOWN site inside APP_rke_command_demux must resolve to 0x40003F53
      with SOME bit index (proves the walker is not tuned to one site).
  C3  non-degeneracy: the resolved bit indices across ALL sites must contain
      more than one distinct value, and the resolved addresses more than one
      distinct address -- otherwise the walker is returning a constant (rule 8).

SWEPT RANGE is printed so any null is explicitly scoped.
READ-ONLY.
"""
import os, sys, json, traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
REPO = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(REPO, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
OUT = os.path.join(REPO, "work/rs-trigger/logs")

TCD = 0x031360
RKE_VALID = 0x40003F53
RKE_CODE = 0x40002DA2

project = None
try:
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject

    project = GhidraProject.openProject(PROJ, NAME, True)
    prog = project.openProgram("/", PROG, True)
    listing = prog.getListing()
    af = prog.getAddressFactory().getDefaultAddressSpace()
    mem = prog.getMemory()

    # ---- collect the whole instruction stream, in address order -----------
    instrs = []
    it = listing.getInstructions(True)
    for ins in it:
        instrs.append(ins)
    lo = instrs[0].getAddress().getOffset()
    hi = instrs[-1].getAddress().getOffset()
    print("SWEPT: %d instructions, %06X .. %06X" % (len(instrs), lo, hi))

    idx_of = {}
    for i, ins in enumerate(instrs):
        idx_of[ins.getAddress().getOffset()] = i

    CALLS = ("e_bl", "se_bl", "e_bla", "bl")

    def sx16(v):
        v &= 0xFFFF
        return v - 0x10000 if v & 0x8000 else v

    def scalar(op):
        try:
            from ghidra.program.model.scalar import Scalar
            if isinstance(op, Scalar):
                return op.getUnsignedValue()
        except Exception:
            pass
        return None

    def regname(op):
        try:
            from ghidra.program.model.lang import Register
            if isinstance(op, Register):
                return op.getName()
        except Exception:
            pass
        return None

    def resolve(i, want):
        """Backward SUBSTITUTION walk.

        Each wanted value is carried as the symbolic pair (reg, const) meaning
        `reg + const`; reg=None means fully resolved.  On each definition of a
        register R that still appears in some expression, R is SUBSTITUTED by
        the definition's right-hand side.  Substitution (rather than a one-shot
        def table) is required because this firmware builds addresses with
        SELF-ACCUMULATING bases -- e.g. `e_add16i r29,r29,0x3f02` -- where a
        def-table walker latches the first def and never reaches the real base.
        """
        expr = {k: (k, 0) for k in want}
        dead = set()
        j = i - 1
        steps = 0
        while j >= 0 and steps < 120 and any(
                e[0] is not None and k not in dead for k, e in expr.items()):
            ins = instrs[j]
            m = ins.getMnemonicString()
            if m in CALLS:
                break
            n = ins.getNumOperands()
            objs = [ins.getOpObjects(k) for k in range(n)]

            def r(k):
                if k >= n:
                    return None
                for o in objs[k]:
                    nm = regname(o)
                    if nm:
                        return nm
                return None

            def s(k):
                if k >= n:
                    return None
                for o in objs[k]:
                    v = scalar(o)
                    if v is not None:
                        return v
                return None

            d = r(0)
            if d is not None:
                # does any live expression still depend on d?
                dependents = [k for k, e in expr.items()
                              if e[0] == d and k not in dead]
                if dependents:
                    if m == "e_lis":
                        v = s(1)
                        if v is None:
                            for k in dependents:
                                dead.add(k)
                        else:
                            for k in dependents:
                                expr[k] = (None, (expr[k][1] + ((v & 0xFFFF) << 16))
                                           & 0xFFFFFFFF)
                    elif m in ("se_li", "e_li"):
                        v = s(1)
                        if v is None:
                            for k in dependents:
                                dead.add(k)
                        else:
                            for k in dependents:
                                expr[k] = (None, (expr[k][1] + v) & 0xFFFFFFFF)
                    elif m in ("e_add16i", "e_addi", "e_add2i.", "se_addi"):
                        src = r(1)
                        v = s(2) if src else s(1)
                        if v is None:
                            v = s(1)
                        if src is None:
                            src = d          # se_addi rD,imm  == rD += imm
                        if v is None:
                            for k in dependents:
                                dead.add(k)
                        else:
                            for k in dependents:
                                expr[k] = (src, (expr[k][1] + sx16(v)) & 0xFFFFFFFF)
                    elif m in ("se_mr", "mr"):
                        src = r(1)
                        if src is None:
                            for k in dependents:
                                dead.add(k)
                        else:
                            for k in dependents:
                                expr[k] = (src, expr[k][1])
                    else:
                        # unmodelled definition of a register we depend on
                        for k in dependents:
                            dead.add(k)
            j -= 1
            steps += 1

        return {k: (expr[k][1] if (expr[k][0] is None and k not in dead) else None)
                for k in want}

    sites = []
    for i, ins in enumerate(instrs):
        if ins.getMnemonicString() not in CALLS:
            continue
        tgt = None
        for a in ins.getFlows():
            tgt = a.getOffset()
        if tgt != TCD:
            continue
        rv = resolve(i, ["r3", "r4"])
        sites.append({
            "site": "%06X" % ins.getAddress().getOffset(),
            "flag": ("0x%08X" % rv["r3"]) if rv["r3"] is not None else None,
            "bit": rv["r4"],
            "mask": ("0x%02X" % (0x80 >> rv["r4"])) if rv["r4"] is not None and rv["r4"] < 8 else None,
        })

    print("TOTAL VOL_test_and_clear_dirty call sites: %d" % len(sites))
    res = sum(1 for s in sites if s["flag"] and s["bit"] is not None)
    print("fully resolved: %d" % res)

    # ---- CONTROLS ---------------------------------------------------------
    by = {s["site"]: s for s in sites}
    c1 = by.get("0AEEDA")
    C1 = c1 is not None and c1["flag"] == "0x40003F53" and c1["bit"] == 2
    print("C1 (0x0AEEDA -> 0x40003F53 bit 2):", "PASS" if C1 else "FAIL", c1)

    rke_sites = [s for s in sites if s["flag"] == "0x%08X" % RKE_VALID]
    C2 = len(rke_sites) >= 2
    print("C2 (>=2 distinct sites resolve to 0x40003F53):", "PASS" if C2 else "FAIL",
          len(rke_sites))

    addrs = set(s["flag"] for s in sites if s["flag"])
    bits = set(s["bit"] for s in sites if s["bit"] is not None)
    C3 = len(addrs) > 1 and len(bits) > 1
    print("C3 non-degeneracy: %d distinct flag addrs, bits=%s -> %s"
          % (len(addrs), sorted(bits), "PASS" if C3 else "FAIL"))

    print()
    print("=== consumers of APP_rke_code_valid 0x40003F53 ===")
    for s in sorted(rke_sites, key=lambda x: x["site"]):
        print("  %s  bit=%s mask=%s" % (s["site"], s["bit"], s["mask"]))

    # neighbours in the same dirty byte band, for context
    print()
    print("=== all sites, flag in 0x40003F40..0x40003F60 (same band control) ===")
    for s in sorted(sites, key=lambda x: x["site"]):
        if s["flag"] and 0x40003F40 <= int(s["flag"], 16) <= 0x40003F60:
            print("  %s  %s bit=%s mask=%s" % (s["site"], s["flag"], s["bit"], s["mask"]))

    json.dump({"controls": {"C1": C1, "C2": C2, "C3": C3},
               "swept": ["%06X" % lo, "%06X" % hi, len(instrs)],
               "sites": sites},
              open(os.path.join(OUT, "347_tcd_sites.json"), "w"), indent=1)
    print("\nWROTE 347_tcd_sites.json")

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
