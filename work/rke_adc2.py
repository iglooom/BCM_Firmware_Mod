"""Re-audit whether PI15 (ADC0_S[23]) is sampled, INCLUDING the eDMA path.

Why this supersedes work/rke_adc.py:
  1. WRONG CHANNEL NUMBER. The datasheet signal name is ADC0_S[23] ("Standard"
     channel 23), NOT absolute channel 23. On SPC560B64:
         ADC0_P[0..15]  -> absolute channels  0..15  (precision)
         ADC0_S[0..27]  -> absolute channels 32..59  (standard)
         ADC0_X[0..3]   -> absolute channels 64..67  (extended)
     So PI15 = ADC0_S[23] = ABSOLUTE CHANNEL 55, and CDR55 = 0xFFE0_01DC.
     The old script tested CDR23 = 0xFFE0_015C, which is inside the RM's
     "0x0140...0x017F Reserved" hole - a register that does not exist. Its
     negative result was therefore meaningless.
  2. NO CDR READ IS REQUIRED. If the ADC feeds eDMA (DMAE/DMAR), results land
     in RAM with no CDR load anywhere in the code. Enumerating CDR consumers
     cannot rule the channel out. A channel is ARMED BY A BITMASK in NCMR,
     not by an address, so address scans miss it too.

So: check the channel-config table for 55, the NCMR/CIMR/DMAR masks, and
whether ADC DMA is enabled at all. Read-only.
"""
import struct
from collections import defaultdict

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()

ADC0 = 0xFFE00000
ADC1 = 0xFFE04000
DEFAULT_CONFIG = 0x16B28

REG = {0x00: "MCR", 0x04: "MSR", 0x10: "ISR", 0x20: "IMR", 0x40: "DMAE",
       0x44: "DMAR0", 0x48: "DMAR1", 0x4C: "DMAR2",
       0xA4: "NCMR0", 0xA8: "NCMR1", 0xAC: "NCMR2",
       0xB4: "JCMR0", 0xB8: "JCMR1", 0xBC: "JCMR2"}
for i in range(16):
    REG[0x100 + 4 * i] = "CDR%d" % i
for i in range(32, 60):
    REG[0x180 + 4 * (i - 32)] = "CDR%d" % i


def sig_to_abs(kind, n):
    return {"P": 0, "S": 32, "X": 64}[kind] + n


PI15_CH = sig_to_abs("S", 23)          # = 55
PI15_CDR = ADC0 + 0x180 + 4 * (PI15_CH - 32)

print("=" * 74)
print("PI15 = ADC0_S[23] -> ABSOLUTE channel %d ; CDR%d @ 0x%08X"
      % (PI15_CH, PI15_CH, PI15_CDR))
print("  (old rke_adc.py tested channel 23 / 0x%08X = RESERVED, not a register)"
      % (ADC0 + 0x100 + 4 * 23))
print("=" * 74)

# ---- 1. channel configuration table -------------------------------------
u = struct.unpack_from
unit_cfg, group_cfg, chan_cfg = u(">III", raw, DEFAULT_CONFIG)
n_groups, n_chans, n_units = u(">BBB", raw, DEFAULT_CONFIG + 0xC)
print("\n[1] default ADC config @0x%X : units=%d groups=%d channels=%d"
      % (DEFAULT_CONFIG, n_units, n_groups, n_chans))
print("    unit_cfg=0x%X group_cfg=0x%X chan_cfg=0x%X" % (unit_cfg, group_cfg, chan_cfg))
configured = defaultdict(list)
for i in range(n_chans):
    off = chan_cfg + i * 6
    ch, unit = u(">BB", raw, off)
    configured[unit].append(ch)
    sig = ("P[%d]" % ch if ch < 16 else
           "S[%d]" % (ch - 32) if 32 <= ch < 60 else
           "X[%d]" % (ch - 64) if 64 <= ch < 68 else "?")
    print("    rec[%02d] @0x%X ADC%d ch %-3d = ADC%d_%-7s settings=%s"
          % (i, off, unit, ch, unit, sig, raw[off + 2:off + 6].hex()))
print("    ADC0 configured channels: %s" % sorted(configured[0]))
print("    ADC1 configured channels: %s" % sorted(configured[1]))
print("    >>> channel %d (PI15) configured: %s"
      % (PI15_CH, PI15_CH in configured[0]))

# ---- 2. every ADC register address present as a literal -----------------
print("\n[2] ADC register addresses present as 32-bit literals in the image")
found = defaultdict(list)
for i in range(len(raw) - 3):
    v = u(">I", raw, i)[0]
    if ADC0 <= v < ADC1 + 0x4000:
        found[v].append(i)
if not found:
    print("    (none - ADC is reached via a base held in a register/table)")
for v in sorted(found):
    unit = 0 if v < ADC1 else 1
    off = v - (ADC0 if unit == 0 else ADC1)
    print("    0x%08X ADC%d.%-7s x%d @%s"
          % (v, unit, REG.get(off, "+0x%X" % off), len(found[v]),
             ",".join(hex(o) for o in found[v][:4])))

# ---- 3. is the ADC->eDMA path enabled at all? ---------------------------
print("\n[3] ADC DMA path")
print("    DMAE  @0x%08X : %s" % (ADC0 + 0x40,
      "literal present" if (ADC0 + 0x40) in found else "no literal"))
for nm, o in (("DMAR0", 0x44), ("DMAR1", 0x48), ("DMAR2", 0x4C)):
    print("    %-5s @0x%08X : %s" % (nm, ADC0 + o,
          "literal present" if (ADC0 + o) in found else "no literal"))
print("    NOTE: channel %d would be DMAR1/NCMR1/CIMR1 bit %d (0x%08X)"
      % (PI15_CH, PI15_CH - 32, 1 << (PI15_CH - 32)))
print("    A DMA-fed channel produces NO CDR read, so absence of CDR%d reads" % PI15_CH)
print("    is NOT evidence. The decisive test is the NCMR1 mask value.")
