#!/usr/bin/env python3
"""Verify sa-1's ACTUAL claim (its report, not its JSON summary).

The JSON said "0x113594 stores literal 3".  My 330 check found e_lis r29,0x4000
there -- NOT a store.  But the report body says something different and much
better: the writer of 3 is an INDIRECT store at 0x113F5E inside FUN_00113EA8,
reached from FUN_0011367E via a pointer passed at call site 0x1136DA, storing
a COMPUTED value `src_byte & 3` (so 0..3, hence 3 is reachable).

That is a materially different claim and it must be checked on its own terms.
The JSON/report mismatch is itself the finding: a self-report's SUMMARY can
misstate its own evidence.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"


def main():
    project = GhidraProject.openProject(
        os.path.join(ROOT, "ghidra_proj_fullflash"), "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        L = program.getListing()

        def show(lo, hi, title):
            print("\n=== %s ===" % title)
            a = lo
            while a < hi:
                i = L.getInstructionAt(af.getAddress(a))
                if i is None:
                    a += 2
                    continue
                print("   0x%06X  %s" % (a, i))
                a += i.getLength()

        show(0x113F48, 0x113F66, "writer 3: indirect store at 0x113F5E")
        show(0x1136C8, 0x1136E4, "call site 0x1136DA passing the pointer")
        show(0x113586, 0x1135B4, "the known literal-4 writer 0x1135AE")

        print("\n=== is 0x113594 a store at all? (the JSON's claim) ===")
        i = L.getInstructionAt(af.getAddress(0x113594))
        print("   0x113594  %s" % i)
        print("   -> %s" % ("IS a store" if i and
                            i.getMnemonicString().lower().startswith(
                                ("e_st", "se_st")) else
                            "NOT a store -> the JSON summary was wrong"))
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
