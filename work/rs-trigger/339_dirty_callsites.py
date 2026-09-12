#!/usr/bin/env python3
"""339 -- enumerate every call site of VOL_test_and_clear_dirty (0x031360) in
BCM_OwnerFlash and resolve (flag_address, bit_number) for each.

Method: ReferenceManager.getReferencesTo() on the callee entry (accept CALL and
JUMP -- rule: do NOT use getCallingFunctions()).  For each call site, walk
backwards over the preceding instructions in the same block resolving r3 (param
1, the flag pointer) and r4 (param 2, the bit index) from
e_lis/e_or2i/e_li/e_add16i/li/lis/addi forms.  Also print the containing
function (may be None in an unswept block -- reported, not hidden).

POSITIVE CONTROLS (same region, same addressing form as the subject):
  C1: a site resolving to flag 0x40003FC0 bit 4  (APP_lock_command_dirty,
      documented level-5 in docs/tx_pack_stage.md Sec.4.1)
  C2: a site resolving to flag 0x40003FF1 bit 2  (documented in
      docs/vehicle_session_1.md Sec.7.4)
Both live in 0x40003Fxx -- the SAME bank as the subject -- and both are reached
through the SAME addressing form (absolute pointer materialised into r3).
If either control fails to resolve, the run is INCONCLUSIVE.

Also: report where APP_rke_code_valid / 0x40003F53 is written and read.
"""
import os
import sys
import traceback
import json

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
CALLEE = 0x031360

OUT = os.path.join(ROOT, "work/rs-trigger/logs/339_dirty_callsites.json")


def resolve_regs(listing, fm, call_addr, depth=40):
    """Walk backwards from the call, emulating a tiny subset of VLE to get r3/r4."""
    regs = {}
    insts = []
    ins = listing.getInstructionBefore(call_addr)
    while ins is not None and len(insts) < depth:
        insts.append(ins)
        ins = listing.getInstructionBefore(ins.getAddress())
    insts.reverse()
    for ins in insts:
        m = ins.getMnemonicString().lower()
        try:
            objs = ins.getOpObjects(0)
            dst = str(objs[0]) if objs else None
        except Exception:
            dst = None
        if dst is None:
            continue
        try:
            if m in ("e_lis", "lis"):
                v = ins.getScalar(1)
                if v is not None:
                    regs[dst] = (v.getUnsignedValue() & 0xFFFF) << 16
            elif m in ("e_or2i", "ori", "e_or2is"):
                v = ins.getScalar(1)
                if v is not None and dst in regs:
                    if m == "e_or2is":
                        regs[dst] |= (v.getUnsignedValue() & 0xFFFF) << 16
                    else:
                        regs[dst] |= v.getUnsignedValue() & 0xFFFF
            elif m in ("e_li", "li", "se_li", "e_lis16"):
                v = ins.getScalar(1)
                if v is not None:
                    regs[dst] = v.getUnsignedValue()
            elif m in ("e_add16i", "addi", "e_addi", "se_addi"):
                # e_add16i rD, rA, imm
                objs = ins.getOpObjects(1)
                src = str(objs[0]) if objs else None
                v = ins.getScalar(2)
                if v is None:
                    v = ins.getScalar(1)
                if src in regs and v is not None:
                    regs[dst] = (regs[src] + v.getSignedValue()) & 0xFFFFFFFF
                elif v is not None and src is None:
                    regs[dst] = v.getUnsignedValue()
            elif m in ("se_mr", "mr"):
                objs = ins.getOpObjects(1)
                src = str(objs[0]) if objs else None
                if src in regs:
                    regs[dst] = regs[src]
                else:
                    regs.pop(dst, None)
            else:
                # any other instruction writing a register invalidates it
                ro = ins.getResultObjects()
                for r in ro:
                    regs.pop(str(r), None)
        except Exception:
            regs.pop(dst, None)
    return regs


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()

        mem = program.getMemory()
        blocks = [(b.getName(), b.getStart(), b.getEnd()) for b in mem.getBlocks()]
        print("SWEPT SCOPE -- memory blocks in %s/%s:" % (NAME, PROG))
        for n, s, e in blocks:
            print("   %-20s %s .. %s" % (n, s, e))
        print("SCAN SCOPE: all references-to 0x%06X across the whole image." % CALLEE)
        print()

        callee = af.getAddress(CALLEE)
        refs = list(rm.getReferencesTo(callee))
        print("getReferencesTo(0x%06X): %d refs" % (CALLEE, len(refs)))
        kinds = {}
        for r in refs:
            kinds[str(r.getReferenceType())] = kinds.get(str(r.getReferenceType()), 0) + 1
        print("  by type:", kinds)
        print()

        rows = []
        for r in refs:
            rt = str(r.getReferenceType())
            if "CALL" not in rt.upper() and "JUMP" not in rt.upper():
                continue
            src = r.getFromAddress()
            f = fm.getFunctionContaining(src)
            regs = resolve_regs(listing, fm, src)
            r3 = regs.get("r3")
            r4 = regs.get("r4")
            rows.append(dict(
                site="0x%06X" % src.getOffset(),
                func=(f.getName() + "@" + str(f.getEntryPoint())) if f else None,
                reftype=rt,
                flag=("0x%08X" % r3) if r3 is not None else None,
                bit=r4,
            ))

        rows.sort(key=lambda d: d["site"])
        print("%-10s %-12s %-3s %s" % ("SITE", "FLAG", "BIT", "FUNC"))
        for d in rows:
            print("%-10s %-12s %-3s %s" % (d["site"], d["flag"], d["bit"], d["func"]))
        print()

        resolved = [d for d in rows if d["flag"]]
        print("resolved %d / %d call sites" % (len(resolved), len(rows)))

        # ---- POSITIVE CONTROLS ----
        c1 = [d for d in rows if d["flag"] == "0x40003FC0" and d["bit"] == 4]
        c2 = [d for d in rows if d["flag"] == "0x40003FF1" and d["bit"] == 2]
        print("CONTROL C1 (0x40003FC0 bit 4, APP_lock_command_dirty): %s" %
              ("PASS " + c1[0]["site"] if c1 else "FAIL"))
        print("CONTROL C2 (0x40003FF1 bit 2):                         %s" %
              ("PASS " + c2[0]["site"] if c2 else "FAIL"))
        if not (c1 and c2):
            print("*** AT LEAST ONE CONTROL FAILED -> result is INCONCLUSIVE ***")

        # ---- SUBJECT: flags in the RKE neighbourhood ----
        print()
        print("Sites whose flag is in 0x40003F40..0x40003F60 (RKE neighbourhood):")
        for d in rows:
            if d["flag"] and 0x40003F40 <= int(d["flag"], 16) <= 0x40003F60:
                print("   ", d)

        # ---- who touches 0x40003F53 at all ----
        print()
        for tgt in (0x40003F53, 0x40003F50, 0x40002DA2, 0x40002DA0):
            a = af.getAddress(tgt)
            rr = list(rm.getReferencesTo(a))
            print("refs to 0x%08X: %d" % (tgt, len(rr)))
            for x in rr:
                s = x.getFromAddress()
                f = fm.getFunctionContaining(s)
                print("    %s %-14s in %s" % (s, x.getReferenceType(),
                                              f.getName() if f else "<unswept>"))

        with open(OUT, "w") as fh:
            json.dump(rows, fh, indent=1)
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
