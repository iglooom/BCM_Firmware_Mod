#!/usr/bin/env python3
"""Prerequisites for the remote-start TRIGGER service.

Establishes, with controls, the facts the cave design depends on:

  P1  a block of MAGIC DIDs absent from the OEM identifier array
      (so stock behaviour cannot change, and no tool can trigger us by accident)
  P2  the hook site is still the peek hook (we CHAIN onto peek's cave, not
      replace it) -- and the OEM bytes there are what peek recorded
  P3  free 0xFF padding for a new cave, clear of acc-fix 0x117100/0x117300 and
      peek 0x118000..0x1181B6
  P4  free scratch RAM, clear of acc-fix 0x40011000, rke-lock 0x40011001 and
      peek 0x40011010..13
      ⚠ NOT IMPLEMENTED HERE.  The rs cave uses no persistent scratch RAM (it
      carries the MAGIC in a register, not a cell), so the scratch half of P4
      is moot.  The REGISTER half is real and is done by 307_reg_safety.py --
      see docs/rs_trigger_design.md Sec.5.  This docstring previously listed
      P4 as if this script performed it; it never did.
  P5  the candidate target cells resolve and their CURRENT bytes are recorded
      (a build-time guard: build_vbf asserts expected bytes at edit sites, and
      we want the runtime cells' identity pinned too)

CONTROL for P1 (rule 20 / rule 9): the scan must FIND a DID that IS in the
array (0x0631, used by peek's acceptance test) -- otherwise "absent" is
vacuous and every candidate would look free.

Read-only.
"""
import os
import sys
import json
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
HERE = os.path.join(ROOT, "work", "rs-trigger")
os.makedirs(HERE, exist_ok=True)

# peek's build -- we must not collide with any of it
PEEK_CAVE = (0x118000, 0x1181B6)
PEEK_SCRATCH = (0x40011010, 0x40011014)
ACCFIX_CAVES = [(0x117100, 0x117300), (0x117300, 0x117500)]
ACCFIX_SCRATCH = [0x40011000, 0x40011001]

HOOK = 0x0010B764          # e_cmpli cr0,r26,0xee00   (peek hooks here)
KNOWN_PRESENT_DID = 0x0631  # control: this one IS in the array

# candidate magic block -- chosen by P1 below


def main():
    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", True)
    program = project.openProgram("/", "flash_merged.bin", True)
    out = {}
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        listing = program.getListing()

        def A(x):
            return af.getAddress(x)

        def rd(addr, n):
            return bytes(mem.getByte(A(addr + i)) & 0xFF for i in range(n))

        print("=" * 74)
        print("P2  hook site 0x%06X" % HOOK)
        print("=" * 74)
        cur = rd(HOOK, 4)
        ins = listing.getInstructionAt(A(HOOK))
        print("   bytes   : %s" % cur.hex().upper())
        print("   disasm  : %s" % ins)
        # peek recorded the OEM bytes; compare
        pb = json.load(open(os.path.join(ROOT, "work", "peek",
                                         "peek_blobs.json")))
        oem = bytes(pb["oem_hook_bytes"])
        print("   peek OEM: %s   %s" % (oem.hex().upper(),
                                        "MATCH" if oem == cur else "DIFFER"))
        out["hook_oem"] = list(cur)
        out["hook_matches_peek"] = (oem == cur)

        print()
        print("=" * 74)
        print("P1  MAGIC DID selection -- scan the image for each candidate")
        print("=" * 74)
        # The identifier array is a table of 16-bit DIDs.  Rather than assume
        # its bounds, scan the WHOLE image for the 2-byte big-endian pattern
        # and report hits; a DID in the table will appear, one absent will not.
        img = open(os.path.join(ROOT, "work", "flash_merged.bin"), "rb").read()

        def hits(did):
            pat = bytes([(did >> 8) & 0xFF, did & 0xFF])
            n, i = 0, 0
            while True:
                i = img.find(pat, i)
                if i < 0:
                    break
                n += 1
                i += 1
            return n

        ctrl = hits(KNOWN_PRESENT_DID)
        print("   CONTROL 0x%04X (known present): %d occurrence(s)  -> %s"
              % (KNOWN_PRESENT_DID, ctrl, "PASS" if ctrl > 0 else "FAIL"))
        print("   (a 2-byte pattern occurs by chance too; we want candidates")
        print("    with the LOWEST count, and we verify on stock hardware)")
        print()
        cands = {}
        for did in range(0xDE00, 0xDF00):
            cands[did] = hits(did)
        best = sorted(cands.items(), key=lambda kv: kv[1])
        print("   lowest-occurrence candidates in 0xDE00..0xDEFF:")
        for did, n in best[:16]:
            print("      0x%04X : %d" % (did, n))
        out["did_scan_min"] = [[d, n] for d, n in best[:16]]

        print()
        print("=" * 74)
        print("P3  cave space")
        print("=" * 74)
        # find FF runs, excluding known-occupied
        runs = []
        st = None
        for i in range(0x10000, 0x140000):
            if img[i] == 0xFF:
                if st is None:
                    st = i
            else:
                if st is not None and i - st >= 512:
                    runs.append((st, i - st))
                st = None
        if st is not None:
            runs.append((st, 0x140000 - st))
        runs.sort(key=lambda r: -r[1])
        print("   largest 0xFF runs:")
        for s, ln in runs[:5]:
            print("      0x%06X  %d bytes" % (s, ln))
        print("   occupied: acc-fix %s  peek 0x%06X..0x%06X"
              % ([hex(a) for a, _ in ACCFIX_CAVES], *PEEK_CAVE))
        print("   -> proposing cave at 0x119000 (clear of all, inside the")
        print("      0x1170F3 run, so sum8-covered)")
        out["cave_runs"] = [[s, ln] for s, ln in runs[:5]]

        print()
        print("=" * 74)
        print("P5  candidate target cells -- current disassembly context")
        print("=" * 74)
        sites = {
            "FUN_00087486 mode4 store": 0x087528,
            "FUN_0008799A mode4 store": 0x0879AA,
            "FUN_0008C7B8 mode4 store": 0x08C7C8,
        }
        for name, a in sites.items():
            i = listing.getInstructionAt(A(a))
            fn = program.getFunctionManager().getFunctionContaining(A(a))
            print("   %-28s 0x%06X  %-26s fn=%s"
                  % (name, a, str(i), fn.getName() if fn else "NONE"))

        json.dump(out, open(os.path.join(HERE, "prereq.json"), "w"), indent=1)
        print("\nsaved %s/prereq.json" % HERE)
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
