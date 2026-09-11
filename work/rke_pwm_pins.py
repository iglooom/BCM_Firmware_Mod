"""Decode the eMIOS PWM channel table -> the firmware's real OUTPUT-driver pins.

From FUN_0003fd3e (PWM init):
    DAT_40004220 = <config table ptr>          ; 0x24-byte records
    count        = *DAT_4000421c
    rec[0] (u32) = eMIOS channel index  (<0x20 -> eMIOS_0 @0xC3FA0000,
                                         >=0x20 -> eMIOS_1, via &DAT_c3fa3c2c
                                         which is 0xC3FA4000-0x400 + ch*0x20)
    rec[1] (u32) = CCR bits (MODE in [6:0], plus edge/prescaler fields)

Channel-register addressing: puVar4[ch*8] with puVar4 = 0xC3FA002C means
    0xC3FA002C + ch*0x20  = eMIOS_0 CCR(ch)      (CCR = chan_base + 0x0C)
so channel n's block is base + 0x20 + n*0x20, matching the RM.

Map each eMIOS channel back to its PACKAGE PIN via the datasheet pin table
(E0UC[n] / E1UC[n] alternate functions), so we can say which physical pins this
BCM drives as PWM/transistor outputs.

Read-only.
"""
import csv
import glob
import os
import re
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()


def u32(o):
    return struct.unpack_from(">I", raw, o)[0]


# ---- locate the table: find the init's pointer loads in flash -----------
# FUN_0003fd3e gets the table from a callee; scan the driver-config region for
# a 0x24-stride array whose first fields are plausible eMIOS channel numbers.
print("=" * 78)
print("candidate eMIOS PWM config tables (0x24 stride, rec[0] = channel < 0x40)")
print("=" * 78)
cands = []
for base in range(0x14000, 0x1C000, 4):
    chans, ok = [], True
    for i in range(24):
        off = base + i * 0x24
        if off + 8 > len(raw):
            ok = False
            break
        ch = u32(off)
        if ch >= 0x40:
            break
        chans.append(ch)
    if len(chans) >= 3 and len(set(chans)) == len(chans):
        ccrs = [u32(base + i * 0x24 + 4) for i in range(len(chans))]
        if all((c & 0x7F) in (0x10, 0x50, 0x52, 0x53, 0x54, 0x58, 0x59, 0x5A, 0x60)
               for c in ccrs):
            cands.append((base, chans, ccrs))

for base, chans, ccrs in cands:
    print("\n  table @0x%05X  (%d records)" % (base, len(chans)))
    for i, (ch, ccr) in enumerate(zip(chans, ccrs)):
        mod = 0 if ch < 0x20 else 1
        print("    rec[%02d] eMIOS_%d ch%-2d  CCR=0x%08X MODE=0x%02X"
              % (i, mod, ch & 0x1F, ccr, ccr & 0x7F))

# ---- datasheet: which pins carry E0UC[n] / E1UC[n] ----------------------
print("\n" + "=" * 78)
print("datasheet: package pins offering eMIOS unified-channel functions")
print("=" * 78)
tbl = {}
for fn in glob.glob(ROOT + "/DS_spc560b64l7_tables/page*_table0.csv"):
    try:
        rows = list(csv.reader(open(fn, encoding="utf-8", errors="replace")))
    except Exception:
        continue
    for r in rows:
        line = ",".join(r)
        m = re.search(r"P([A-J])\[(\d+)\],PCR\[(\d+)\]", line)
        if not m:
            continue
        pad = "P%s%s" % (m.group(1), m.group(2))
        for em in re.findall(r"E([01])UC\[(\d+)\]", line):
            tbl.setdefault(("E%sUC" % em[0], int(em[1])), []).append(pad)

for key in sorted(tbl):
    print("  %-6s[%2d] -> %s" % (key[0], key[1], ", ".join(sorted(set(tbl[key])))))
if not tbl:
    print("  (no E0UC/E1UC rows parsed)")
