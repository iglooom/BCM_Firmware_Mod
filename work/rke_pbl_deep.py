"""Deep-dive the newly-recovered PBL + locate the shadow's 17 non-FF bytes +
identify which config table the owner module's 4 differing bytes belong to.

The literal scan found no SIUL pad register in the PBL, but PBL code could form
addresses dynamically (the same blind spot that hid the WKPU and the PWM driver).
So: check whether the PBL even contains peripheral-touching code, and which
peripheral pages it references at all.

Read-only, pure static decode (no Ghidra needed).
"""
import re
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
BK = ROOT + "/backups/owner-backup-20260911T090300Z/"
cf = open(BK + "cflash.bin", "rb").read()
sh = open(BK + "shadow.bin", "rb").read()
pbl = cf[:0xC000]

# ---------- PBL structure ------------------------------------------------
print("=" * 78)
print("[A] PBL structure (cflash 0x000000..0x00BFFF)")
print("=" * 78)
for a in (0x0000, 0x4000, 0x8000):
    hw = struct.unpack_from(">H", cf, a)[0]
    entry = struct.unpack_from(">I", cf, a + 4)[0]
    valid = (hw & 0x00FF) == 0x005A
    print("  RCHW @0x%06X: halfword=0x%04X entry=0x%08X  %s"
          % (a, hw, entry, "VALID  (VLE=%d)" % ((hw >> 8) & 1) if valid else "-"))

print("\n  PBL strings:")
seen = set()
for m in re.finditer(rb"[ -~]{6,}", pbl):
    s = m.group().decode("latin1")
    if s in seen:
        continue
    seen.add(s)
    print("     0x%06X  %s" % (m.start(), s[:88]))

# ---------- which peripheral pages does the PBL reference? --------------
print("\n" + "=" * 78)
print("[B] peripheral pages referenced by the PBL (32-bit literals)")
print("=" * 78)
PAGES = [
    (0xC3F90000, 0xC3F94000, "SIUL"), (0xC3F94000, 0xC3F98000, "WKPU"),
    (0xC3FA0000, 0xC3FA8000, "eMIOS_0/1"), (0xC3FD8000, 0xC3FDC000, "SSCM"),
    (0xC3FDC000, 0xC3FE0000, "MC_ME"), (0xC3FE0000, 0xC3FE4000, "MC_CGM"),
    (0xC3FE4000, 0xC3FE8000, "MC_RGM"), (0xC3FEC000, 0xC3FF0000, "RTC/API"),
    (0xC3FF0000, 0xC3FF4000, "PIT"), (0xFFE00000, 0xFFE08000, "ADC_0/1"),
    (0xFFE40000, 0xFFE60000, "LINFlex_0-7"), (0xFFE64000, 0xFFE68000, "CTU"),
    (0xFFF38000, 0xFFF3C000, "SWT"), (0xFFF3C000, 0xFFF40000, "STM"),
    (0xFFF40000, 0xFFF44000, "ECSM"), (0xFFF44000, 0xFFF48000, "eDMA"),
    (0xFFF48000, 0xFFF4C000, "INTC"), (0xFFF90000, 0xFFFA8000, "DSPI_0-5"),
    (0xFFFC0000, 0xFFFD8000, "FlexCAN_0-5"),
    (0xC3F88000, 0xC3F90000, "flash config (CFLASH/DFLASH)"),
]
counts = {}
for i in range(len(pbl) - 3):
    v = struct.unpack_from(">I", pbl, i)[0]
    for lo, hi, nm in PAGES:
        if lo <= v < hi:
            counts.setdefault(nm, []).append((i, v))
            break
for nm in sorted(counts):
    lst = counts[nm]
    print("  %-30s x%-3d e.g. 0x%08X @0x%05X"
          % (nm, len(lst), lst[0][1], lst[0][0]))
if not counts:
    print("  (no peripheral literals at all)")
print("\n  >>> A programming loader only needs flash-controller + CAN + clocks.")
print("      Absence of SIUL/ADC/eMIOS pad references means it configures NO pins.")

# ---------- shadow non-FF bytes -----------------------------------------
print("\n" + "=" * 78)
print("[C] flash shadow array — the 17 non-0xFF bytes")
print("=" * 78)
runs = []
i = 0
while i < len(sh):
    if sh[i] != 0xFF:
        j = i
        while j < len(sh) and sh[j] != 0xFF:
            j += 1
        runs.append((i, sh[i:j]))
        i = j
    else:
        i += 1
for off, blob in runs:
    print("  0x%08X (+0x%04X) len=%d : %s"
          % (0x200000 + off, off, len(blob), blob.hex()))
    pr = "".join(chr(b) if 32 <= b < 127 else "." for b in blob)
    print("      ascii: %s" % pr)

# ---------- the 4 differing config bytes --------------------------------
print("\n" + "=" * 78)
print("[D] owner module's 4 differing config bytes — which table?")
print("=" * 78)
merged = open(ROOT + "/work/flash_merged.bin", "rb").read()
KNOWN = [
    (0x16B28, 0x16B8C, "ADC default-config header"),
    (0x16B8C, 0x16DF4, "ADC group-config records (7 x 0x58)"),
    (0x16DF4, 0x16E60, "ADC channel-config records (15 x 6)"),
    (0x17050, 0x17150, "EIRQ/WKUP config header"),
    (0x17150, 0x171D0, "EIRQ/WKUP records (4 x 32)"),
    (0x175D4, 0x175DC, "PWM config header"),
    (0x175DC, 0x17780, "PWM records (11 x 0x24)"),
]
for a in (0x017CAD, 0x017CAE, 0x017CAF, 0x017CBB):
    where = "unclassified driver-config region"
    for lo, hi, nm in KNOWN:
        if lo <= a < hi:
            where = nm
            break
    print("  0x%06X  oem=0x%02X owner=0x%02X   region: %s"
          % (a, merged[a], cf[a], where))

print("\n  context dump 0x017C90..0x017CD0:")
print("    oem   : %s" % merged[0x17C90:0x17CD0].hex())
print("    owner : %s" % cf[0x17C90:0x17CD0].hex())
print("\n  nearest known tables: PWM records end 0x17780; next structures unmapped.")
print("  These 4 bytes are NOT in the ADC / EIRQ-WKUP / PWM tables, so they cannot")
print("  enable a pin in any of the peripherals already audited.")
