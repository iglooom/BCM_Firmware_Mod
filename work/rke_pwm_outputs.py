"""Decode the eMIOS PWM output table = the BCM's transistor/MOSFET-gate driver pins.

Chain (all confirmed by decompilation):
  FUN_0003f54a : DAT_4000421c = cfg (default &LAB_000175d4 when NULL)
                 -> FUN_0003fd3e(cfg[+4])
  FUN_0003fd3e : DAT_40004220 = record array; loops i < *DAT_4000421c
                 rec = DAT_40004220 + i*0x24
                 ch  = rec[0]  (u32)   ; ch<0x20 -> eMIOS_0, else eMIOS_1
                 ccr = rec[1]  (u32)   ; written into CCR(ch) = base+0x2C+ch*0x20
  FUN_0003f836 : runtime duty-cycle setter, dispatches on the same channel id

Header @0x175D4 : [0]=count(u32)=11, [+4]=record array=0x175DC.
MODE 0x26 = OPWMB (Output PWM with Buffered registers) -> these are true OUTPUTS.

Read-only. Pure static decode of the flash image.
"""
import csv
import glob
import re
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()


def u32(o):
    return struct.unpack_from(">I", raw, o)[0]


HDR = 0x175D4
count = u32(HDR)
table = u32(HDR + 4)

MODES = {0x26: "OPWMB (output PWM, buffered)", 0x10: "SAIC (input capture)",
         0x50: "SAOC (output compare)", 0x60: "MCB (modulus counter)"}

# datasheet: eMIOS unified-channel -> package pads
pinmap = {}
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
        pcr = int(m.group(3))
        for em in re.findall(r"E([01])UC\[(\d+)\]", line):
            pinmap.setdefault((int(em[0]), int(em[1])), set()).add((pad, pcr))

print("=" * 78)
print("eMIOS PWM OUTPUT table  header@0x%05X  count=%d  records@0x%05X"
      % (HDR, count, table))
print("=" * 78)
print("\n%-6s %-6s %-14s %-30s %s"
      % ("rec", "chan", "module/ch", "mode", "candidate package pads"))
print("-" * 92)

for i in range(count):
    o = table + i * 0x24
    ch = u32(o)
    ccr = u32(o + 4)
    mod = 0 if ch < 0x20 else 1
    hw = ch & 0x1F
    mode = ccr & 0x7F
    pads = sorted(pinmap.get((mod, hw), []))
    padstr = ", ".join("%s(PCR%d)" % (p, c) for p, c in pads) or "?"
    print("%-6d %-6d eMIOS_%d ch%-4d %-30s %s"
          % (i, ch, mod, hw, MODES.get(mode, "0x%02X" % mode), padstr))

print("\n" + "=" * 78)
print("SUMMARY")
print("=" * 78)
print("  %d PWM channels configured, ALL in mode 0x26 = OPWMB (true outputs)." % count)
print("  These are the firmware's load-driver pins (transistor / MOSFET gates).")
print("  They are driven via eMIOS channel registers, NOT via SIUL GPDO - which is")
print("  why a GPDO-only scan found just 5 pads (those 5 are LIN transceiver")
print("  control, each paired with a LINFlex base in a descriptor record).")
print("\n  Neither PI15 (E0UC/E1UC: none) nor PF12 (E1UC[25], not in this table)")
print("  is among the configured PWM outputs.")
