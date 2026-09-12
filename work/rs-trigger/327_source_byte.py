#!/usr/bin/env python3
"""327 -- can the SOURCE byte produce 3?

The pointer writer is:
    0x113F4C  se_lbz r5,0xb(r7)      r7 = 0x4000B0B0 + idx*0xE
    0x113F58  e_andi r7,r5,0x3
    0x113F5E  se_stb r7,0x0(r6)      r6 = &DAT_40002F3C   (idx==1)

So the stored value is (byte @ 0x4000B0B0 + idx*0xE + 0xB) & 3, range 0..3.
For idx=1 the source byte is 0x4000B0BB + 0xE = ... careful:
    base 0x40010000-0x4F50 = 0x4000B0B0 ; +idx*0xE ; +0xB
    idx=0 -> 0x4000B0BB   idx=1 -> 0x4000B0C9   idx=2 -> 0x4000B0D7
(Ghidra's decompiler printed it as (&DAT_4000b0bb)[uVar4*0xe], same thing.)

3 is stored IF AND ONLY IF that source byte's low 2 bits can be 0b11.
This finds its writers and the values they set.

Controls: the same scan is run for idx=0 and idx=2 source bytes, whose
DESTINATION cells (0x40002F32, 0x40002F37) are the already-validated siblings.

Read-only.
"""
import os
import re
import sys
import traceback
from collections import defaultdict

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
PROJ = os.path.join(ROOT, "ghidra_proj_fullflash")

ARR = 0x4000B0B0
SRC = {ARR + i * 0xE + 0xB: "src for idx=%d" % i for i in range(3)}
# whole struct array, to catch memset/block writers
LOW, HIGH = ARR, ARR + 3 * 0xE

STORE_MN = ("e_stb", "e_sth", "e_stw", "se_stb", "se_sth", "se_stw",
            "e_stbu", "e_sthu", "e_stwu")
DISP_RE = re.compile(r"^(-?)0x([0-9a-fA-F]+)\((r\d+)\)$")


def parse_disp(t):
    m = DISP_RE.match(t.strip().lower())
    if not m:
        m = re.match(r"^(-?)(\d+)\((r\d+)\)$", t.strip().lower())
        if not m:
            return None, None
        s, mag, r = m.groups()
        return (-int(mag) if s == "-" else int(mag)), r
    s, mag, r = m.groups()
    v = int(mag, 16)
    return (-v if s == "-" else v), r


def main():
    project = GhidraProject.openProject(PROJ, "BCM_OwnerFlash", True)
    program = project.openProgram("/", "cflash.bin", True)
    try:
        af = program.getAddressFactory().getDefaultAddressSpace()
        listing = program.getListing()
        fm = program.getFunctionManager()
        refmgr = program.getReferenceManager()

        print("=" * 78)
        print("A. references to the 3 source bytes")
        print("=" * 78)
        for a, d in SRC.items():
            print("\n 0x%08X  %s" % (a, d))
            for r in refmgr.getReferencesTo(af.getAddress(a)):
                fa = r.getFromAddress()
                i = listing.getInstructionAt(fa)
                fn = fm.getFunctionContaining(fa)
                print("    0x%06X  %-26s fn=%s"
                      % (fa.getOffset(), str(i) if i else "-",
                         fn.getName() if fn else "UNSWEPT"))

        print()
        print("=" * 78)
        print("B. FULL-IMAGE base+disp sweep: any store landing in")
        print("   0x%08X..0x%08X  (the whole 3x0xE struct array)" % (LOW, HIGH))
        print("=" * 78)
        fn_entries = set(f.getEntryPoint().getOffset()
                         for f in fm.getFunctions(True))
        regs = {}
        prev_end = None
        hits = defaultdict(list)
        it = listing.getInstructions(True)
        while it.hasNext():
            ins = it.next()
            off = ins.getAddress().getOffset()
            if off in fn_entries or prev_end is None or off != prev_end:
                regs = {}
            prev_end = off + ins.getLength()
            mn = ins.getMnemonicString().lower()
            try:
                d0 = ins.getDefaultOperandRepresentation(0).strip().lower()
            except Exception:
                d0 = ""
            if mn.startswith(STORE_MN):
                try:
                    t = ins.getDefaultOperandRepresentation(1).strip().lower()
                except Exception:
                    t = ""
                disp, reg = parse_disp(t)
                if reg in regs and disp is not None:
                    ea = (regs[reg] + disp) & 0xFFFFFFFF
                    if LOW <= ea <= HIGH:
                        fn = fm.getFunctionContaining(ins.getAddress())
                        # what defines the stored register?
                        src = d0
                        p = ins
                        prod = "?"
                        for _ in range(20):
                            p = p.getPrevious()
                            if p is None:
                                break
                            pm = p.getMnemonicString().lower()
                            try:
                                pd = p.getDefaultOperandRepresentation(
                                    0).strip().lower()
                            except Exception:
                                pd = ""
                            if pd == src and not pm.startswith(
                                    STORE_MN + ("e_cmp", "se_cmp", "e_b",
                                                "se_b")):
                                prod = "%s @0x%06X" % (
                                    str(p), p.getAddress().getOffset())
                                break
                        hits[ea].append((off, str(ins),
                                         fn.getName() if fn else "UNSWEPT",
                                         prod))
                continue
            if mn in ("e_lis", "se_lis", "lis"):
                try:
                    regs[d0] = (int(ins.getScalar(1).getValue()) << 16) & 0xFFFFFFFF
                except Exception:
                    regs.pop(d0, None)
            elif mn in ("e_add16i", "e_addi", "addi"):
                try:
                    s = ins.getDefaultOperandRepresentation(1).strip().lower()
                    v = int(ins.getScalar(2).getValue())
                    if s in regs:
                        regs[d0] = (regs[s] + v) & 0xFFFFFFFF
                    else:
                        regs.pop(d0, None)
                except Exception:
                    regs.pop(d0, None)
            elif mn.startswith(("e_cmp", "se_cmp", "cmp", "e_b", "se_b")):
                pass
            elif d0.startswith("r"):
                regs.pop(d0, None)
        tot = sum(len(v) for v in hits.values())
        print("   stores landing in the array: %d" % tot)
        for ea in sorted(hits):
            mark = "  <<< SOURCE BYTE" if ea in SRC else ""
            print("\n   0x%08X (array+0x%02X)%s" % (ea, ea - ARR, mark))
            for h in hits[ea]:
                print("     0x%06X  %-26s fn=%-22s src<- %s"
                      % (h[0], h[1], h[2], h[3]))
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
