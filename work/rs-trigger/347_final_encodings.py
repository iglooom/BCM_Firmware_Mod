#!/usr/bin/env python3
"""347 -- final encodings: the 'set only bit n=2' variant using se_bseti, and a
restatement of the bit-numbering convention derived from the primitive itself.

VOL_test_and_clear_dirty(byte *p, byte n):  mask = (byte)(0x80 >> n)
  n=0 -> 0x80   n=1 -> 0x40   n=2 -> 0x20   n=3 -> 0x10
  n=4 -> 0x08   n=5 -> 0x04   n=6 -> 0x02   n=7 -> 0x01
So the codec's n is MSB-FIRST (n=0 is the most significant bit of the byte).
The equivalent LSB-first hardware bit index is (7 - n).
PowerPC se_bseti rX,k sets bit k counting from the LSB of the 32-bit register,
so announcing codec-bit n on a byte loaded into a register needs k = 7 - n.
"""
import os
import sys
import traceback

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402
import jpype  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.app.plugin.assembler import Assemblers  # noqa: E402
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")
NAME = "BCM_OwnerFlash"
PROG = "cflash.bin"

LINES = [
    "e_lis r3,0x4000",
    "e_add16i r3,r3,0x3f53",
    "se_lbz r0,0x0(r3)",
    "se_bseti r0,0x5",
    "se_stb r0,0x0(r3)",
    "se_bmaski r0,0x8",
    "se_li r0,0x0",
    "e_stb r0,0x0(r3)",
]


def main():
    project = GhidraProject.openProject(PROJ, NAME, True)
    program = project.openProgram("/", PROG, True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        mem = program.getMemory()
        asm = Assemblers.getAssembler(program.getLanguage())
        JB = jpype.JArray(jpype.JByte)
        CTX = AssemblyPatternBlock.fromBytes(0, JB([0x20, 0, 0, 0]))
        at = af.getAddress(0x058560)

        chunk = 0x10000
        parts = []
        off = 0
        while off < 0x180000:
            arr = JB(chunk)
            got = mem.getBytes(af.getAddress(off), arr)
            parts.append(bytes([(int(x) & 0xFF) for x in arr[:got]]))
            off += chunk
        data = b"".join(parts)

        print("bit-numbering convention (from VOL_test_and_clear_dirty @0x031360):")
        for n in range(8):
            print("   n=%d -> mask 0x%02X  (LSB-first bit %d)" % (n, 0x80 >> n, 7 - n))
        print()

        print("%-24s %-10s %s" % ("LINE", "BYTES", "independent disassembler check"))
        for line in LINES:
            try:
                b = bytes([x & 0xFF for x in asm.assembleLine(at, line, CTX)])
            except Exception as e:
                print("  %-24s ASSEMBLE FAILED %s" % (line, str(e)[:70]))
                continue
            # image round trip
            verdict = "NOT FOUND in image"
            start = 0
            while True:
                i = data.find(b, start)
                if i < 0:
                    break
                start = i + 1
                if i & 1:
                    continue
                ins = listing.getInstructionAt(af.getAddress(i))
                if ins is not None and ins.getLength() == len(b):
                    norm = lambda s: s.lower().replace(" ", "").replace("0x0(", "0(")
                    verdict = ("MATCH @0x%06X : %s" % (i, ins)) if \
                        norm(str(ins)) == norm(line) else \
                        ("MISMATCH @0x%06X : %s" % (i, ins))
                    break
            print("  %-24s %-10s %s" % (line, b.hex(), verdict))
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
