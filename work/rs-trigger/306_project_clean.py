#!/usr/bin/env python3
"""Confirm ghidra_proj/BCM_C1MCA was NOT modified by the build scripts.

301_build_cave.py and 304_verify.py both open this project WRITABLE and write
cave bytes into the program, relying on endTransaction(tid, False) to roll the
changes back.  Neither calls project.save().  If either rollback silently
failed, the project would now contain our patch bytes -- and this is the
project the shipped acc-fix / rke-lock VBFs are built and verified against
(AGENTS.md rule 5), so a silent corruption would invalidate future
verification runs without any visible symptom.

AGENTS.md Sec.2.1: "after any bulk Ghidra write, reopen the project read-only
and re-read the counts" -- every write-path failure in this project reported
success on stdout.

ASSERTS (read-only):
  * the peek hook site still holds the OEM bytes 189AA9EE
  * the peek cave span is still all-0xFF
  * the rs cave span is still all-0xFF
  * the setaddr() self-check scratch at 0x11A000 is still all-0xFF
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
HOOK = 0x0010B764
OEM_HOOK = bytes([0x18, 0x9A, 0xA9, 0xEE])

# ⚠ Span lengths are DERIVED from the build artifacts, never hard-coded.  The
# first version had (0x119000, 298) baked in; when depth 4 grew the cave to 416
# bytes this check silently verified only the first 298 and reported CLEAN,
# leaving 118 bytes unexamined.  Same failure class as 304's hand-maintained
# V1 target list: an expectation copied by hand goes stale the moment the
# artifact changes, and a stale checker reports success.
def _spans():
    import json
    pk = json.load(open(os.path.join(ROOT, "work", "peek", "peek_blobs.json")))
    out = [(pk["cave_addr"], len(pk["cave"]), "peek cave")]
    rsp = os.path.join(ROOT, "work", "rs-trigger", "rs_blobs.json")
    if os.path.exists(rsp):
        rs = json.load(open(rsp))
        out.append((rs["cave_addr"], len(rs["cave"]), "rs cave"))
    out.append((0x0011A000, 16, "setaddr self-check scratch"))
    return out


def main():
    rc = 0
    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", True)   # READ-ONLY
    program = None
    try:
        program = project.openProgram("/", "flash_merged.bin", True)
        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()

        def rd(a, n):
            return bytes(mem.getByte(af.getAddress(a + i)) & 0xFF
                         for i in range(n))

        print("=" * 68)
        print("ghidra_proj/BCM_C1MCA -- post-build cleanliness check")
        print("=" * 68)

        got = rd(HOOK, 4)
        ok = got == OEM_HOOK
        rc |= 0 if ok else 1
        print("  hook 0x%06X  %s  %s"
              % (HOOK, got.hex().upper(), "OEM (clean)" if ok
                 else "*** MODIFIED -- project is dirty ***"))

        for base, ln, name in _spans():
            span = rd(base, ln)
            nff = sum(1 for b in span if b != 0xFF)
            ok = nff == 0
            rc |= 0 if ok else 1
            print("  %-28s 0x%06X+%-4d %s"
                  % (name, base, ln,
                     "all 0xFF (clean)" if ok
                     else "*** %d non-FF bytes -- DIRTY ***" % nff))

        print()
        if rc:
            print("  RESULT: PROJECT IS DIRTY.  Do not trust it for")
            print("  acc-fix / rke-lock verification until restored.")
        else:
            print("  RESULT: CLEAN -- all rollbacks took effect.")
        print("=" * 68)
    except Exception:
        traceback.print_exc()
        rc = 2
    finally:
        try:
            project.close()
        except Exception:
            pass
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(rc)


main()
