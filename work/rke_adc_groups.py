"""DECISIVE test for PI15 = ADC0_S[23] = absolute channel 55.

From the real ADC driver FUN_0003a402, the conversion masks are NOT hardcoded:
they are copied out of a GROUP CONFIG RECORD (stride 0x58, array @0x16B8C,
7 groups) into the hardware:

    normal   groups:  record[+0x24] -> NCMR0 (0xFFE000A4)
                      record[+0x28] -> NCMR1 (0xFFE000A8)
    injected groups:  record[+0x24] -> JCMR0 (0xFFE000B4)
                      record[+0x28] -> JCMR1 (0xFFE000B8)
                      record[+0x2C] -> JCMR2 (0xFFE000BC)
                      record[+0x30] -> PSR0,  record[+0x34] -> PSR1

Absolute channel 55 lives in the *1 registers at bit (55-32)=23, mask 0x00800000.
If no group record has that bit set, ADC0 never samples PI15 - regardless of
whether results are read via CDR or moved by eDMA.

Also enumerates the eDMA / DMAMUX footprint, since a DMA-fed channel leaves no
CDR read behind and would defeat a consumer-based search. Read-only.
"""
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()
u = struct.unpack_from

GROUP_CFG, N_GROUPS, STRIDE = 0x16B8C, 7, 0x58
PI15_CH = 55
PI15_MASK = 1 << (PI15_CH - 32)          # 0x00800000 in the *1 registers


def chans(mask, base):
    return [base + i for i in range(32) if mask & (1 << i)]


def sig(ch):
    if ch < 16:
        return "P[%d]" % ch
    if 32 <= ch < 60:
        return "S[%d]" % (ch - 32)
    if 64 <= ch < 68:
        return "X[%d]" % (ch - 64)
    return "ch%d?" % ch


print("=" * 78)
print("DECISIVE: does any ADC group arm absolute channel %d (PI15 = ADC0_S[23])?"
      % PI15_CH)
print("  -> needs bit 23 (mask 0x%08X) set in a record's +0x28 word (NCMR1/JCMR1)"
      % PI15_MASK)
print("=" * 78)

hit = False
for g in range(N_GROUPS):
    r = GROUP_CFG + g * STRIDE
    m0, m1, m2 = u(">III", raw, r + 0x24)
    extra0, extra1 = u(">II", raw, r + 0x30)
    ch_list = chans(m0, 0) + chans(m1, 32) + chans(m2, 64)
    print("\n  group[%d] @0x%X" % (g, r))
    print("    +0x24 (NCMR0/JCMR0) = 0x%08X -> %s" % (m0, chans(m0, 0)))
    print("    +0x28 (NCMR1/JCMR1) = 0x%08X -> %s" % (m1, chans(m1, 32)))
    print("    +0x2C (NCMR2/JCMR2) = 0x%08X -> %s" % (m2, chans(m2, 64)))
    print("    +0x30/+0x34 (PSR)   = 0x%08X / 0x%08X" % (extra0, extra1))
    print("    signals: %s" % ", ".join(sig(c) for c in ch_list) if ch_list else
          "    signals: (none)")
    if m1 & PI15_MASK:
        hit = True
        print("    *** CHANNEL 55 / PI15 ARMED IN THIS GROUP ***")

print("\n" + "=" * 78)
print("RESULT: channel %d (PI15) armed in ANY group: %s" % (PI15_CH, hit))
print("=" * 78)

# ---- eDMA / DMAMUX footprint --------------------------------------------
print("\n[eDMA path] SPC560B eDMA @0xFFF44000, DMAMUX @0xFFFDC000")
WINDOWS = {"eDMA": (0xFFF44000, 0xFFF48000), "DMAMUX": (0xFFFDC000, 0xFFFDC100)}
for name, (lo, hi) in WINDOWS.items():
    offs = [i for i in range(len(raw) - 3) if lo <= u(">I", raw, i)[0] < hi]
    print("  %-7s literals in image: %d %s" % (name, len(offs),
          [hex(o) for o in offs[:8]]))
    if not offs:
        print("           -> no %s register address anywhere; DMA not configured"
              " by literal address" % name)

adc_dmae = 0xFFE00040
for nm, a in (("ADC0.DMAE", adc_dmae), ("ADC0.DMAR0", 0xFFE00044),
              ("ADC0.DMAR1", 0xFFE00048), ("ADC0.DMAR2", 0xFFE0004C)):
    n = raw.count(struct.pack(">I", a))
    print("  %-11s 0x%08X literal count = %d" % (nm, a, n))
print("\n  NOTE: driver writes ADC regs via base+displacement, so also check the")
print("  decompiled init: FUN_0003a402 touches MCR/IMR/CIMR/NCMR/JCMR/PSR/CTR only")
print("  - it never writes DMAE (+0x40) or DMAR (+0x44/48/4C).")
