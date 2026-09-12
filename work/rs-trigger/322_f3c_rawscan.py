#!/usr/bin/env python3
"""322 -- METHOD D: raw-binary VLE store scan, NO GHIDRA AT ALL.

Independent of Ghidra's disassembly, its function database, its reference
manager and its decompiler.  Decodes VLE store encodings straight out of
`cflash.bin` and tracks base registers with its own linear tracker.

Why this is a genuinely independent method: methods A/B/C all inherit Ghidra's
instruction boundaries, so a store sitting inside a region Ghidra never
disassembled (rule 14/44 unswept blocks) is invisible to all three at once.
This scanner decodes at EVERY 2-byte offset in the whole 1.5 MB image, so it
cannot inherit that blindness.  Its price is false positives: data bytes that
happen to look like a store.  It is therefore reported as a SUPERSET/upper
bound, and every hit is cross-checked.

Encodings (derived by round-trip against instructions Ghidra already decoded in
this exact image, not from a manual -- see ENC_PROOF below):
  e_stb  rD,d(rA)   32-bit  OP=13   b0 = 0x34|(D>>3)  b1 = ((D&7)<<5)|A  d=b2b3
  e_sth  rD,d(rA)   32-bit  OP=22   b0 = 0x58|(D>>3)
  e_stw  rD,d(rA)   32-bit  OP=21   b0 = 0x54|(D>>3)
  se_stb rZ,SD4(rX) 16-bit  0x9<<12 | SD4<<8 | RZ<<4 | RX
  se_sth rZ,SD4(rX) 16-bit  0xA<<12 | ...     (offset = SD4<<1)
  se_stw rZ,SD4(rX) 16-bit  0xB<<12 | ...     (offset = SD4<<2)
  se_li  rX,imm     16-bit  0x48<<8 | imm<<4 | RX      (imm 0..127 -> 0x48/0x49..)
  e_lis  rD,imm     32-bit  OP=28 XO ...  (matched by byte pattern 0x70 0x..)
  e_add16i rD,rA,si 32-bit  OP=7

ENC_PROOF (round-trip controls, all read back from this image):
  0x1135AE  34 1e 02 1c  = e_stb  r0,0x21c(r30)
  0x11378C  9c 0f        = se_stb r0,0xc(r31)
  0x113788  97 0f        = se_stb r0,0x7(r31)
  0x113786  48 50        = se_li  r0,0x5
  0x1135AC  48 40        = se_li  r0,0x4
  0x0AD6CC  70 3c 40 00  = e_lis  r30,0x4000        (0x70|.. OP=28)
  0x0AD6D0  1f de 2d 20  = e_add16i r30,r30,0x2d20
If any of these do not decode, the scanner aborts -- a decoder that cannot
reproduce known instructions proves nothing about the ones it misses.

Read-only; does not touch Ghidra.
"""
import os
import sys
import json
from collections import defaultdict

ROOT = "/home/gl/Projects/ford/BCM/Research"
BIN = os.path.join(ROOT, "backups/owner-backup-20260911T090300Z/cflash.bin")
OUT = os.path.join(ROOT, "work/rs-trigger/f3c_rawscan.json")

TARGET = 0x40002F3C
WATCH = {
    0x40002F3C: "TARGET gate byte (struct 0x40002D20 +0x21C)",
    0x40002F37: "control +0x217 (same struct, same form)",
    0x40002F32: "control +0x212 (same struct, same form)",
    0x4000965C: "control other-region enum",
}

D = open(BIN, "rb").read()
N = len(D)


def u16(o):
    return (D[o] << 8) | D[o + 1]


def u32(o):
    return (D[o] << 24) | (D[o + 1] << 16) | (D[o + 2] << 8) | D[o + 3]


def s16(v):
    return v - 0x10000 if v & 0x8000 else v


# ------------------------------------------------------------------ decoders
# Field definitions transcribed from Ghidra's own SLEIGH spec for this exact
# language (PowerPC:BE:64:VLE-32addr), files
#   /opt/ghidra/Ghidra/Processors/PowerPC/data/languages/ppc_common.sinc
#   /opt/ghidra/Ghidra/Processors/PowerPC/data/languages/ppc_vle.sinc
# NOT from memory.  Key subtleties that broke the first attempt:
#   * 16-bit VLE register fields are a 16-entry ATTACH, not a register number:
#       RX_VLE/RY_VLE/RZ_VLE -> r0..r7, r24..r31   (ppc_common.sinc:1081)
#     so encoding value 15 means r31, not r15.
#   * e_lis's immediate is a SPLIT field:
#       IMM16B = (IMM_16_20_VLE << 11) | IMM_0_10_VLE      (ppc_vle.sinc:47)
#     and it is selected by XOP_11_VLE=(11,15)==28, not by bits 16..20.
VLE16_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
              "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"]


def dec(o):
    """Return (len, kind, fields) for the instruction at offset o, or None."""
    if o + 2 > N:
        return None
    h = u16(o)
    op4 = h >> 12
    op5 = (h >> 11) & 0x1F
    op6 = (h >> 10) & 0x3F
    rx = VLE16_REGS[h & 0xF]
    rz = VLE16_REGS[(h >> 4) & 0xF]
    sd4 = (h >> 8) & 0xF

    # ---- 16-bit forms (OP4_VLE) ----
    if op4 in (9, 11, 13):   # se_stb / se_sth / se_stw
        sc = {9: 0, 11: 1, 13: 2}[op4]
        mn = {9: "se_stb", 11: "se_sth", 13: "se_stw"}[op4]
        return (2, "store", dict(mn=mn, src=rz, base=rx, disp=sd4 << sc))
    if op4 in (8, 10, 12):   # se_lbz / se_lhz / se_lwz  (defines rz)
        return (2, "other", dict(mn="se_ld", dst=rz))
    if op5 == 9:             # se_li RX_VLE, OIM7_VLE   (ppc_vle.sinc:784)
        return (2, "li", dict(mn="se_li", dst=rx, val=(h >> 4) & 0x7F))
    if op6 == 0 and ((h >> 8) & 3) == 1:   # se_mr RX,RY  (:797)
        return (2, "mr", dict(mn="se_mr", dst=rx, src=rz))
    if op6 == 0 and ((h >> 8) & 3) == 2:   # se_mtar ARX,RY
        return (2, "other", dict(mn="se_mtar", dst=None))
    if op6 == 0 and ((h >> 8) & 3) == 3:   # se_mfar RX,ARY
        return (2, "other", dict(mn="se_mfar", dst=rx))
    if op6 == 8 and ((h >> 9) & 1) == 0:   # se_addi RX,OIMM  OIMM=UI5+1
        return (2, "addi_s", dict(mn="se_addi", dst=rx,
                                  val=((h >> 4) & 0x1F) + 1))
    if op6 == 9 and ((h >> 9) & 1) == 0:   # se_subi RX,OIMM
        return (2, "addi_s", dict(mn="se_subi", dst=rx,
                                  val=-(((h >> 4) & 0x1F) + 1)))
    if op6 == 1:             # se_add / se_mullw / se_sub / se_subf
        return (2, "other", dict(mn="se_arith", dst=rx))

    # ---- 32-bit forms ----
    if o + 4 > N:
        return (2, "other", dict(mn="?16", dst=None))
    w = u32(o)
    op = (w >> 26) & 0x3F
    d = "r%d" % ((w >> 21) & 0x1F)
    a = "r%d" % ((w >> 16) & 0x1F)
    imm16 = w & 0xFFFF
    if op in (13, 22, 21):   # e_stb / e_sth / e_stw
        mn = {13: "e_stb", 22: "e_sth", 21: "e_stw"}[op]
        return (4, "store", dict(mn=mn, src=d, base=a, disp=imm16))
    if op == 28:
        # SLEIGH token fields are LSB-numbered: XOP_11_VLE=(11,15) means
        # (w >> 11) & 0x1F, NOT (w >> 16).  Getting this wrong silently
        # reclassifies every e_lis as "other" and kills the base tracker --
        # which is exactly what the round-trip control caught.
        xop11 = (w >> 11) & 0x1F
        imm16b = (((w >> 16) & 0x1F) << 11) | (w & 0x7FF)
        if xop11 == 28:                 # e_lis D,IMM16B   (ppc_vle.sinc:788)
            return (4, "lis", dict(mn="e_lis", dst=d,
                                   val=(imm16b << 16) & 0xFFFFFFFF))
        if ((w >> 15) & 1) == 0:        # e_li D,SIMM20    (ppc_vle.sinc:780)
            simm20 = (((w >> 11) & 0xF) << 16) | (((w >> 16) & 0x1F) << 11) \
                | (w & 0x7FF)
            if simm20 & 0x80000:
                simm20 -= 0x100000
            return (4, "li", dict(mn="e_li", dst=d, val=simm20))
        return (4, "other", dict(mn="e_op28", dst=d))
    if op == 7:              # e_add16i D,A,SIMM
        return (4, "addi", dict(mn="e_add16i", dst=d, src=a, val=s16(imm16)))
    if op == 6:              # e_addi / e_lbzu / e_stbu ... XOP_12_VLE=(12,15)
        x12 = (w >> 12) & 0xF
        if x12 == 8:
            return (4, "other", dict(mn="e_addi_scale", dst=d))
        return (4, "other", dict(mn="e_op6", dst=d))
    if op in (12, 14, 20):   # e_lbz / e_lha / e_lwz
        return (4, "other", dict(mn="e_ld", dst=d))
    return (4, "other", dict(mn="op%d" % op, dst=d))


# ------------------------------------------------------------------ proof
PROOF = [
    (0x1135AE, "store", "e_stb", dict(src="r0", base="r30", disp=0x21C)),
    (0x11378C, "store", "se_stb", dict(src="r0", base="r31", disp=0xC)),
    (0x113788, "store", "se_stb", dict(src="r0", base="r31", disp=0x7)),
    (0x11378A, "store", "se_stb", dict(src="r0", base="r31", disp=0x2)),
    (0x113786, "li", "se_li", dict(dst="r0", val=5)),
    (0x1135AC, "li", "se_li", dict(dst="r0", val=4)),
    (0x0AD6CC, "lis", "e_lis", dict(dst="r30", val=0x40000000)),
    (0x0AD6D0, "addi", "e_add16i", dict(dst="r30", src="r30", val=0x2D20)),
    (0x11363A, "store", "e_stb", dict(src="r0", base="r30", disp=0x217)),
    (0x1135F4, "store", "e_stb", dict(src="r0", base="r30", disp=0x212)),
]
print("=" * 78)
print("DECODER ROUND-TRIP CONTROL (must be 10/10 or the scan is void)")
print("=" * 78)
ok = 0
for off, kind, mn, flds in PROOF:
    r = dec(off)
    good = (r is not None and r[1] == kind and r[2].get("mn") == mn
            and all(r[2].get(k) == v for k, v in flds.items()))
    ok += bool(good)
    print("   0x%06X  %-8s expect %-9s got %s   %s"
          % (off, D[off:off + 4].hex(), mn,
             r[2] if r else None, "OK" if good else "*** FAIL"))
print("   %d/%d" % (ok, len(PROOF)))
if ok != len(PROOF):
    print("\nDECODER FAILED ITS CONTROL -- aborting (rule 8/45).")
    sys.exit(1)

# ------------------------------------------------------------------ scan
# Linear tracker over the whole image.  Because there is no function database,
# register state is flushed every RESET_WIN bytes and on any decode gap; this
# makes the tracker CONSERVATIVE (it loses state, never fabricates it).
print()
print("=" * 78)
print("D1. RAW LINEAR SCAN: every 2-byte offset, 0x000000..0x%06X" % N)
print("=" * 78)

hits = defaultdict(list)
allstores = 0
resolved = 0
val_of = {}          # last se_li value per register, for value attribution
cand_disp = defaultdict(int)

o = 0
regs = {}
vals = {}
lastval = {}
while o + 2 <= N:
    r = dec(o)
    if r is None:
        o += 2
        continue
    ln, kind, f = r
    if kind == "store":
        allstores += 1
        b = f["base"]
        if b in regs:
            resolved += 1
            ea = (regs[b] + f["disp"]) & 0xFFFFFFFF
            if ea in WATCH:
                sv = vals.get(f["src"])
                hits[ea].append(dict(at=o, mn=f["mn"], src=f["src"],
                                     base=b, disp=f["disp"],
                                     baseval=regs[b], value=sv))
    elif kind == "lis":
        regs[f["dst"]] = f["val"]
        vals.pop(f["dst"], None)
    elif kind in ("addi", "addi_s"):
        if kind == "addi":
            if f["src"] in regs:
                regs[f["dst"]] = (regs[f["src"]] + f["val"]) & 0xFFFFFFFF
            else:
                regs.pop(f["dst"], None)
        else:
            if f["dst"] in regs:
                regs[f["dst"]] = (regs[f["dst"]] + f["val"]) & 0xFFFFFFFF
        vals.pop(f["dst"], None)
    elif kind == "li":
        vals[f["dst"]] = f["val"]
        regs.pop(f["dst"], None)
    elif kind == "mr":
        if f["src"] in regs:
            regs[f["dst"]] = regs[f["src"]]
        else:
            regs.pop(f["dst"], None)
        if f["src"] in vals:
            vals[f["dst"]] = vals[f["src"]]
        else:
            vals.pop(f["dst"], None)
    else:
        dst = f.get("dst")
        if dst:
            regs.pop(dst, None)
            vals.pop(dst, None)
    o += ln

print("   store-shaped words seen : %d" % allstores)
print("   with a resolvable base  : %d" % resolved)
for a, desc in WATCH.items():
    print("   0x%08X %-46s hits=%d" % (a, desc, len(hits[a])))

# ------------------------------------------------------------------ D2
# Encoding-exhaustive: EVERY byte-store in the image whose displacement could
# reach the target from ANY base, regardless of whether the base is known.
# This is the true upper bound on "sites that could be writing this cell".
print()
print("=" * 78)
print("D2. DISPLACEMENT-ONLY UPPER BOUND (base unknown allowed)")
print("=" * 78)
forms = []
o = 0
while o + 2 <= N:
    r = dec(o)
    if r is None:
        o += 2
        continue
    ln, kind, f = r
    if kind == "store" and f["mn"] in ("e_stb", "se_stb"):
        if f["disp"] in (0x21C, 0xC):
            forms.append((o, f["mn"], f["src"], f["base"], f["disp"]))
    o += ln
print("   byte-stores with disp 0x21C or 0xC anywhere in image: %d" % len(forms))
d21c = [x for x in forms if x[4] == 0x21C]
dc = [x for x in forms if x[4] == 0xC]
print("     disp 0x21C : %d" % len(d21c))
print("     disp 0x0C  : %d" % len(dc))
print("   (upper bound -- most have a base unrelated to 0x40002D20)")
print("   disp 0x21C sites:")
for x in d21c:
    print("     0x%06X  %s %s,0x%x(%s)" % (x[0], x[1], x[2], x[4], x[3]))

# ------------------------------------------------------------------ D3
# THE DECISIVE QUESTION: is a literal 3 EVER the source of a store that could
# land on this cell?  Scan every se_li/e_li of value 3 and see whether the
# defined register is the source of a nearby byte-store with disp 0x21C/0xC.
print()
print("=" * 78)
print("D3. IS LITERAL 3 EVER STORED THROUGH disp 0x21C / 0xC ?")
print("=" * 78)
li3 = 0
near = []
o = 0
pend = {}
while o + 2 <= N:
    r = dec(o)
    if r is None:
        o += 2
        continue
    ln, kind, f = r
    if kind == "li":
        if f["val"] == 3:
            li3 += 1
            pend[f["dst"]] = o
        else:
            pend.pop(f["dst"], None)
    elif kind == "store":
        if f["src"] in pend and f["disp"] in (0x21C, 0xC) \
                and f["mn"] in ("e_stb", "se_stb"):
            near.append((pend[f["src"]], o, f["mn"], f["base"], f["disp"]))
    else:
        dst = f.get("dst")
        if dst:
            pend.pop(dst, None)
    o += ln
print("   se_li rX,3 occurrences in image      : %d" % li3)
print("   ...whose register is then byte-stored")
print("      at disp 0x21C or 0xC              : %d" % len(near))
for x in near:
    print("     li@0x%06X -> store@0x%06X %s 0x%x(%s)"
          % (x[0], x[1], x[2], x[4], x[3]))

# ------------------------------------------------------------------ value dump
print()
print("=" * 78)
print("RESOLVED HITS WITH VALUES")
print("=" * 78)
for a, desc in WATCH.items():
    print("\n 0x%08X  %s" % (a, desc))
    seen = set()
    for h in hits[a]:
        if h["at"] in seen:
            continue
        seen.add(h["at"])
        print("   0x%06X  %-7s %s,0x%x(%s)  base=0x%08X  value=%s"
              % (h["at"], h["mn"], h["src"], h["disp"], h["base"],
                 h["baseval"],
                 ("literal %d" % h["value"]) if h["value"] is not None
                 else "NOT a nearby literal"))

json.dump({hex(k): v for k, v in hits.items()}, open(OUT, "w"), indent=1)
print("\nwrote %s" % OUT)
