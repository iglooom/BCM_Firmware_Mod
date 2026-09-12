#!/usr/bin/env python3
"""341 -- reference-based resolution of EVERY VOL_test_and_clear_dirty call site.

Why a second pass: 339 resolved r3 by backwards constant-folding over a 40
instruction window.  That form only works when the flag pointer is materialised
absolutely (e_lis + e_add16i).  Many sites use the STRUCT-FIELD form
`e_addi r3, r28, 0xbe` off a base register set up in the prologue -- exactly the
addressing form AGENTS.md warns about -- and 339 returned None for all of them
(177 of 782).  That is why CONTROL C1 (0x40003FC0 bit 4 @ 0x04C62C) "failed":
a METHOD blindness, not an absence.

This pass instead reads GHIDRA'S OWN resolved PARAM/data references on the
instructions preceding each call, which the decompiler/constant-propagation
analyser has already resolved through the register base.  It therefore covers
BOTH addressing forms.

SWEPT SCOPE: every reference to 0x031360 in the whole program (all blocks;
printed below).  A null result is a claim about that scope only.

POSITIVE CONTROLS (both in 0x40003Fxx, the same bank as the subject):
  C1 absolute-form  : 0x40003FF1 bit 2 @ 0x0AE92C   (docs/vehicle_session_1.md 7.4)
  C2 base+disp form : 0x40003FC0 bit 4 @ 0x04C630   (docs/tx_pack_stage.md 4.1)
Subject uses the absolute form (0x099308) AND, if present, base+disp sites --
so BOTH forms must have a passing control.
"""
import os
import sys
import traceback
import json
from collections import Counter

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
CALLEE = 0x031360
OUT = os.path.join(ROOT, "work/rs-trigger/logs/341_dirty_sites.json")

SRAM_LO, SRAM_HI = 0x40000000, 0x40018000


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()

        print("SWEPT SCOPE -- blocks:")
        for b in program.getMemory().getBlocks():
            print("   %-12s %s..%s" % (b.getName(), b.getStart(), b.getEnd()))
        print("SCAN: all refs to VOL_test_and_clear_dirty @0x%06X\n" % CALLEE)

        callee = af.getAddress(CALLEE)
        sites = []
        for r in rm.getReferencesTo(callee):
            rt = str(r.getReferenceType()).upper()
            if "CALL" not in rt and "JUMP" not in rt:
                continue
            src = r.getFromAddress()
            f = fm.getFunctionContaining(src)

            # walk back up to 12 instructions collecting (a) the LAST SRAM-range
            # reference Ghidra resolved (the r3 flag pointer) and (b) the last
            # immediate loaded into r4.
            flag = None
            bit = None
            form = None
            ins = listing.getInstructionBefore(src)
            n = 0
            while ins is not None and n < 12:
                mn = ins.getMnemonicString().lower()
                objs = ins.getOpObjects(0)
                dst = str(objs[0]) if objs else None
                if bit is None and dst == "r4" and mn in (
                        "se_li", "e_li", "li", "e_lis"):
                    sc = ins.getScalar(1)
                    if sc is not None:
                        bit = sc.getUnsignedValue()
                if flag is None and dst == "r3":
                    for rr in ins.getReferencesFrom():
                        off = rr.getToAddress().getOffset()
                        if SRAM_LO <= off < SRAM_HI:
                            flag = off
                            form = ("absolute" if mn in ("e_add16i", "e_or2i",
                                                         "ori")
                                    and "r3,r3" in str(ins).replace(" ", "")
                                    else "base+disp")
                            break
                    # crude but explicit form classification
                    if flag is not None:
                        s = str(ins).replace(" ", "")
                        form = "absolute" if s.startswith("e_add16ir3,r3,") \
                            else "base+disp"
                if flag is not None and bit is not None:
                    break
                ins = listing.getInstructionBefore(ins.getAddress())
                n += 1
            sites.append(dict(site="0x%06X" % src.getOffset(),
                              func=(f.getName() + "@" + str(f.getEntryPoint()))
                              if f else None,
                              flag=("0x%08X" % flag) if flag is not None else None,
                              bit=bit, form=form))

        sites.sort(key=lambda d: d["site"])
        with open(OUT, "w") as fh:
            json.dump(sites, fh, indent=1)

        res = [d for d in sites if d["flag"] is not None and d["bit"] is not None]
        print("call sites: %d   fully resolved: %d   (%.1f%%)"
              % (len(sites), len(res), 100.0 * len(res) / max(1, len(sites))))
        print("by addressing form:", Counter(d["form"] for d in res))
        print()

        def ck(addr, bit, label):
            hit = [d for d in res if d["flag"] == addr and d["bit"] == bit]
            print("CONTROL %-34s : %s" % (label,
                  ("PASS at " + hit[0]["site"] + " form=" + str(hit[0]["form"]))
                  if hit else "FAIL"))
            return bool(hit)

        ok1 = ck("0x40003FF1", 2, "C1 abs 0x40003FF1 bit2")
        ok2 = ck("0x40003FC0", 4, "C2 base+disp 0x40003FC0 bit4")
        if not (ok1 and ok2):
            print("*** CONTROL FAILURE -> INCONCLUSIVE ***")
        print()

        print("=== ALL sites whose flag is APP_rke_code_valid 0x40003F53 ===")
        subj = [d for d in res if d["flag"] == "0x40003F53"]
        for d in subj:
            print("   ", d)
        if not subj:
            print("    (none)")
        print()
        print("=== unresolved flag pointer (reported, not hidden) ===")
        unres = [d for d in sites if d["flag"] is None]
        print("    %d sites" % len(unres))
        for d in unres[:25]:
            print("   ", d)

        print()
        print("=== bit histogram for flag 0x40003F53 across whole image ===")
        print(Counter(d["bit"] for d in subj))

        print()
        print("=== neighbourhood: all flags in 0x40003F40..0x40003F60 ===")
        for d in sorted(res, key=lambda x: (x["flag"], x["bit"])):
            if 0x40003F40 <= int(d["flag"], 16) <= 0x40003F60:
                print("    %-12s bit %-2s  %-10s %-12s %s"
                      % (d["flag"], d["bit"], d["site"], d["form"], d["func"]))
        print("\nwrote", OUT)
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


if __name__ == "__main__":
    main()
