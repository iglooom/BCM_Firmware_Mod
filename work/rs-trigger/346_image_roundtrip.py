#!/usr/bin/env python3
"""346 -- TRUE round trip by IMAGE SEARCH.

344 produced candidate encodings with Ghidra's assembler.  345's attempt to
re-parse them via Language.parse() failed on a JPype overload, so this script
does the round trip a different and arguably stronger way: it searches CFLASH
for each exact byte string at a 2-byte-aligned offset that Ghidra has ALREADY
disassembled as an instruction, and prints Ghidra's own rendering of it.

If Ghidra independently disassembles those same bytes elsewhere in the image as
the mnemonic we asked the assembler for, the encoding is confirmed by a second,
independent path (disassembler vs assembler).

Patterns that do NOT occur in the image are reported as NOT-FOUND -- that is an
honest 'unconfirmed by this method', NOT a failure of the encoding.

SWEPT SCOPE: CFLASH 0x00000000..0x0017FFFF, every 2-byte-aligned offset.
POSITIVE CONTROL: '341e0051' (e_stb r0,0x51(r30)) is known to exist at
0x05856A; if the search does not find it there, the search is broken.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"
IMG = os.path.join(ROOT, "work/owner/cflash.bin")

CASES = [
    ("e_lis r30,0x4000", "73c8e000"),
    ("e_add16i r30,r30,0x3f02", "1fde3f02"),
    ("se_bmaski r0,0x8", "2c80"),
    ("e_stb r0,0x51(r30)", "341e0051"),   # CONTROL, must hit 0x05856A
    ("e_lis r3,0x4000", "7068e000"),
    ("e_add16i r3,r3,0x3f53", "1c633f53"),
    ("se_stb r0,0x0(r3)", "9003"),
    ("se_lbz r0,0x0(r3)", "8003"),
    ("e_ori r0,r0,0x20", "1800d020"),
]


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        mem = program.getMemory()

        # read CFLASH out of the loaded program (no external file needed)
        lo, hi = 0x00000000, 0x00180000
        import jpype
        JB = jpype.JArray(jpype.JByte)
        chunk = 0x10000
        parts = []
        off = lo
        while off < hi:
            n = min(chunk, hi - off)
            arr = JB(n)
            got = mem.getBytes(af.getAddress(off), arr)
            parts.append(bytes([(int(x) & 0xFF) for x in arr[:got]]))
            off += n
        data = b"".join(parts)
        print("read %d bytes of CFLASH from the loaded program" % len(data))
        print("SWEPT SCOPE: CFLASH 0x%06X..0x%06X, 2-byte aligned\n" % (lo, hi - 1))

        for want, hexb in CASES:
            pat = bytes.fromhex(hexb)
            hits = []
            start = 0
            while True:
                i = data.find(pat, start)
                if i < 0 or i >= hi:
                    break
                start = i + 1
                if i & 1:
                    continue
                ins = listing.getInstructionAt(af.getAddress(i))
                if ins is None or ins.getLength() != len(pat):
                    continue
                hits.append((i, str(ins)))
                if len(hits) >= 3:
                    break
            if hits:
                a0, t0 = hits[0]
                norm = lambda s: s.lower().replace(" ", "").replace("0x0(", "0(")
                ok = norm(t0) == norm(want)
                print("  %-10s wanted %-26s | Ghidra @0x%06X : %-26s %s  (%d hits)"
                      % (hexb, want, a0, t0, "MATCH" if ok else "MISMATCH",
                         len(hits)))
                for a, t in hits[1:]:
                    print("               also @0x%06X : %s" % (a, t))
            else:
                print("  %-10s wanted %-26s | NOT FOUND in image (unconfirmed "
                      "by this method, not a failure)" % (hexb, want))

        print("\nCONTROL: '341e0051' must be found at 0x05856A -- see above.")
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
