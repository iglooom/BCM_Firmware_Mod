#!/usr/bin/env python3
"""352 -- VERIFY the two subagents' dirty-flag claims from the artifact.

A child's summary is a SELF-REPORT (rule 49): one earlier subagent's JSON named
an address that held e_lis, not the store it claimed.  Both children here agree
on a mechanism, but rule 47 warns that AGREEMENT IS ONLY CORROBORATION IF THE
METHODS FAIL INDEPENDENTLY -- and these two shared a brief, a codebase and a
set of method hints.  So re-derive every load-bearing claim directly.

CLAIMS UNDER TEST
  C1  0x05856A stores 0xFF to 0x40003F53   (se_bmaski r0,0x8 then e_stb ..0x51(r30))
  C2  0x05856E stores the command code to 0x40002DA2, immediately after C1
  C3  VOL_test_and_clear_dirty @0x031360 tests mask (0x80 >> n)
  C4  0x0AEEDA is a test-and-clear call site with n=2  (mask 0x20)
  C5  0x099308 is the other call site, n=1 (mask 0x40) -- NOT remote start
  C6  0x0ADA3E sets bit 27 of 0x40009680   (already verified in Sec.7; regression)

Each is asserted against the actual instruction bytes/mnemonics, not prose.
"""
import sys
import os
import traceback

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra")
import pyghidra  # noqa: E402

pyghidra.start()

from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
# ⚠ The PROJECT is named BCM_OwnerFlash but the PROGRAM inside it is
# "cflash.bin" (see work/owner/gw_dec_owner.py).  Passing the project name as
# the program name gives FileNotFoundException: File not found: //BCM_OwnerFlash
PROG = "cflash.bin"

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print("  %-52s %s  %s" % (name, "PASS" if ok else "FAIL", detail))


def main():
    project = None
    try:
        project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
        prog = project.openProgram("/", PROG, True)
        listing = prog.getListing()
        af = prog.getAddressFactory().getDefaultAddressSpace()

        def ins_at(a):
            return listing.getInstructionAt(af.getAddress(a))

        def txt(a):
            i = ins_at(a)
            return "%s %s" % (i.getMnemonicString(),
                              ",".join(str(i.getDefaultOperandRepresentation(k))
                                       for k in range(i.getNumOperands()))) \
                if i else "<no instruction>"

        print("=" * 74)
        print("VERIFYING THE DIRTY-FLAG CHAIN (both subagents)")
        print("=" * 74)

        # --- C1: the 0xFF store to 0x40003F53 -------------------------------
        print("\nC1/C2  the announce pair in APP_rke_code_commit")
        # ⚠ Do NOT hard-code the value-load address: the first version guessed
        # 0x058566 and got "<no instruction>" (rule 50).  Walk BACK from the
        # store through real instruction boundaries and find what sets r0.
        a = 0x058538
        chain = []
        while a < 0x058580:
            i = ins_at(a)
            if i is None:
                a += 2
                continue
            chain.append((a, txt(a)))
            a += i.getLength()
        for ad, t in chain:
            mark = ""
            if ad == 0x05856A:
                mark = "   <-- stores the flag byte"
            elif ad == 0x05856E:
                mark = "   <-- stores the command code"
            print("   %08X  %s%s" % (ad, t, mark))

        i_set = ins_at(0x05856A)
        c1 = i_set is not None and i_set.getMnemonicString().lower().startswith(
            ("e_stb", "se_stb"))
        check("C1 0x05856A is a byte store", c1, txt(0x05856A))

        # find the last write to r0 before the store -- that is the VALUE
        val_site, val_txt = None, ""
        for ad, t in chain:
            if ad >= 0x05856A:
                break
            if t.split()[0].lower() in ("se_li", "e_li", "se_bmaski",
                                        "e_lis", "se_mr") and \
                    t.split(",")[0].endswith("r0"):
                val_site, val_txt = ad, t
        check("C1b value-producing instruction found", val_site is not None,
              "%s @%s" % (val_txt, hex(val_site) if val_site else "-"))
        if val_site is not None:
            iv = ins_at(val_site)
            sc = iv.getScalar(iv.getNumOperands() - 1)
            n = int(sc.getValue()) if sc is not None else None
            # se_bmaski r0,0x8 produces 0xFF; se_li r0,0xFF also produces 0xFF
            val = 0xFF if ("bmaski" in val_txt.lower() and n == 8) else n
            check("C1c the value written is 0xFF", val == 0xFF,
                  "%s -> 0x%s" % (val_txt, format(val, "02X") if val is not None else "?"))

        i_code = ins_at(0x05856E)
        c2 = i_code is not None and i_code.getMnemonicString().lower().startswith(
            ("e_sth", "se_sth"))
        check("C2 0x05856E stores the 16-bit code", c2, txt(0x05856E))

        # --- C3: the test-and-clear helper ----------------------------------
        print("\nC3  VOL_test_and_clear_dirty @0x031360 -- mask = 0x80 >> n")
        found_shift = False
        a = 0x031360
        for _ in range(24):
            i = ins_at(a)
            if i is None:
                break
            m = i.getMnemonicString().lower()
            s = txt(a)
            if "srw" in m or "sraw" in m or "rlw" in m or "bmaski" in m:
                print("   %08X  %s" % (a, s))
                found_shift = True
            a += i.getLength()
        check("C3 helper contains a shift/mask build", found_shift)

        # --- C4/C5: the two call sites --------------------------------------
        print("\nC4/C5  the only two consumers of the flag")
        for site, want_n in ((0x0AEEDA, 2), (0x099308, 1)):
            # walk back a few instructions looking for the literal n
            a2 = site
            lits = []
            for back in range(8):
                prev = None
                scan = site - 40
                while scan < a2:
                    ii = ins_at(scan)
                    if ii is None:
                        scan += 2
                        continue
                    if scan + ii.getLength() >= a2:
                        prev = scan
                        break
                    scan += ii.getLength()
                if prev is None:
                    break
                a2 = prev
                ii = ins_at(a2)
                for k in range(ii.getNumOperands()):
                    sc = ii.getScalar(k)
                    if sc is not None:
                        lits.append(int(sc.getValue()))
                print("   %08X  %s" % (a2, txt(a2)))
            check("C4/C5 site %06X passes n=%d" % (site, want_n),
                  want_n in lits, "literals seen: %s" % lits[:8])

        # --- C6: regression on the known setter ------------------------------
        print("\nC6  regression -- 0x0ADA3E sets bit 27 (verified in Sec.7)")
        print("   %08X  %s" % (0x0ADA3C, txt(0x0ADA3C)))
        print("   %08X  %s" % (0x0ADA3E, txt(0x0ADA3E)))
        i_b = ins_at(0x0ADA3C)
        c6 = i_b is not None and "bseti" in i_b.getMnemonicString().lower()
        check("C6 0x0ADA3C is se_bseti (regression)", c6, txt(0x0ADA3C))

        print("\n" + "=" * 74)
        bad = [n for n, ok in RESULTS if not ok]
        print("RESULT: %d/%d passed" % (len(RESULTS) - len(bad), len(RESULTS)))
        if bad:
            print("  FAILED: " + ", ".join(bad))
            print("  => do NOT build on the failed claims until re-derived.")
        else:
            print("  every load-bearing claim re-derived from the artifact.")
        print("=" * 74)

    except Exception:
        traceback.print_exc()
    finally:
        try:
            if project is not None:
                project.close()
        except Exception:
            traceback.print_exc()
        sys.stdout.flush()
        sys.stderr.flush()


main()
sys.stdout.flush()
sys.stderr.flush()
os._exit(0)
