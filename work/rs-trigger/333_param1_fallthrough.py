#!/usr/bin/env python3
"""332 returned ZERO callers -- that is the SIGNATURE of a sweep-split block,
not a negative (AGENTS.md rules 19/44).  This is the proper attempt.

FUN_000AD97C is entered by FALLTHROUGH from the preceding block, like the rest
of this module (0x0ADADA / 0x0ADB1E / 0x0ADE12 all have zero CALL/JUMP refs and
are reachable only by byte-adjacency -- remote_start.md Sec.7.0.3).

So: walk BACKWARD from 0x0AD97C through preceding instructions, across block
boundaries, and resolve r3 (EABI arg0).  If a caller genuinely sets up r3 for
this function it will be within a few tens of instructions.

CONTROL (rule 45): the same walker is run on FUN_000ADADA (0x0ADADA), whose
predecessor chain is DOCUMENTED (0x0ADAD8 fallthrough, remote_start.md Sec.
7.0.3 records r7=0x40002D20 resolving there).  If the walker cannot reproduce a
known register binding on that path, its null on r3 is uninformative.

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
EXPECT = 0x400095DC


def main():
    project = GhidraProject.openProject(
        os.path.join(ROOT, "ghidra_proj_fullflash"), "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        L = program.getListing()

        def back_resolve(start, want, limit=160):
            """Walk backward by byte-adjacency; resolve `want` register."""
            addr = start
            partial = {}
            steps = []
            n = 0
            ins = L.getInstructionAt(af.getAddress(addr))
            cur = ins.getPrevious() if ins else None
            while cur is not None and n < limit:
                n += 1
                mn = cur.getMnemonicString().lower()
                try:
                    d0 = cur.getDefaultOperandRepresentation(0).strip().lower()
                except Exception:
                    d0 = ""
                steps.append((cur.getAddress().getOffset(), str(cur)))
                if mn in ("e_add16i", "e_addi", "addi") and d0 == want:
                    try:
                        src = cur.getDefaultOperandRepresentation(1).strip().lower()
                        val = int(cur.getScalar(2).getValue())
                    except Exception:
                        cur = cur.getPrevious()
                        continue
                    p = cur.getPrevious()
                    m = 0
                    while p is not None and m < 80:
                        m += 1
                        if p.getMnemonicString().lower() in ("e_lis", "se_lis",
                                                             "lis"):
                            dd = p.getDefaultOperandRepresentation(0).strip().lower()
                            if dd == src:
                                hi = int(p.getScalar(1).getValue()) << 16
                                return ((hi + val) & 0xFFFFFFFF,
                                        cur.getAddress().getOffset(),
                                        p.getAddress().getOffset(), steps)
                        p = p.getPrevious()
                if mn in ("e_lis", "se_lis", "lis") and d0 == want:
                    try:
                        partial[want] = int(cur.getScalar(1).getValue()) << 16
                    except Exception:
                        pass
                cur = cur.getPrevious()
            return None, None, None, steps

        print("=" * 72)
        print("CONTROL: reproduce the documented r7 = 0x40002D20 at 0x0ADE12")
        print("=" * 72)
        v, a1, a2, _ = back_resolve(0x0ADE12, "r7")
        ctrl_ok = (v == 0x40002D20)
        print("   r7 -> %s  %s" % ("0x%08X" % v if v else "unresolved",
                                   "PASS" if ctrl_ok else "FAIL"))
        if not ctrl_ok:
            print("   ⚠ walker cannot reproduce a KNOWN binding; any null below")
            print("     is uninformative, not a negative.")

        print()
        print("=" * 72)
        print("TARGET: r3 (arg0) entering FUN_000AD97C @ 0x0AD97C")
        print("=" * 72)
        v, a1, a2, steps = back_resolve(0x0AD97C, "r3")
        if v is not None:
            print("   r3 = 0x%08X   (built at 0x%06X / lis 0x%06X)"
                  % (v, a1, a2))
            print("   expected 0x%08X -> %s"
                  % (EXPECT, "*** MATCH -- param_1 PROVEN ***" if v == EXPECT
                     else "MISMATCH"))
        else:
            print("   r3 unresolved within the walk window.")
            print("   preceding instructions (nearest first):")
            for a, t in steps[:16]:
                print("      0x%06X  %s" % (a, t))

        print()
        print("=" * 72)
        print("VERDICT: %s" % (
            "param_1 = 0x%08X PROVEN via fallthrough predecessor" % EXPECT
            if v == EXPECT else
            "still unproven -- Sec.7.5.1's arithmetic match is the only evidence"
            if ctrl_ok else
            "INCONCLUSIVE -- control failed, walker unreliable here"))
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
