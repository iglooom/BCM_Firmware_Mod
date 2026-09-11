"""Final closure: verify ALL backup regions against OEM, and identify the owner
module's 4 differing config bytes (they look like pointers, not pin config).

Context dump showed a 0x20-stride record array at ~0x17C90:
    +0x00 0x00146FA0   +0x04 0x00146FA4   +0x08 0x40007AF9 (RAM)
    +0x0C..+0x17 zeros +0x18 index        +0x1C 0x00141C74 (flash ptr)
Owner differences:
    record[0] +0x1C : 0x00141C74 -> 0x0015BE00   (both inside the F10A cal block)
    record[1] +0x08 : 0x40007AF9 -> 0x40007AFD   (RAM status byte)
So the owner's module selects a DIFFERENT calibration record - variant coding,
not pin enabling.

Read-only.
"""
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
BK = ROOT + "/backups/owner-backup-20260911T090300Z/"
cf = open(BK + "cflash.bin", "rb").read()
merged = open(ROOT + "/work/flash_merged.bin", "rb").read()

print("=" * 78)
print("[1] backup vs OEM, region by region")
print("=" * 78)
REG = [
    (0x000000, 0x00C000, "PBL (no OEM file exists)"),
    (0x00C000, 0x010000, "Cal F124  vs JV6T-14C095-AB"),
    (0x010000, 0x140000, "App      vs JV6T-14C094-AD"),
    (0x140000, 0x15BF4C, "Cal F10A vs JV6T-14C403-AB"),
    (0x15BF4C, 0x180000, "tail (beyond all VBFs)"),
]
for lo, hi, nm in REG:
    if lo >= len(merged):
        seg = cf[lo:hi]
        ff = seg.count(b"\xff")
        print("  0x%06X-0x%06X %-34s  no OEM ref; FF=%.1f%%"
              % (lo, hi, nm, 100 * ff / max(1, len(seg))))
        continue
    end = min(hi, len(merged))
    d = [i for i in range(lo, end) if cf[i] != merged[i]]
    if not d:
        print("  0x%06X-0x%06X %-34s  IDENTICAL" % (lo, hi, nm))
    else:
        print("  0x%06X-0x%06X %-34s  %d differing: %s"
              % (lo, hi, nm, len(d), ", ".join("0x%06X" % x for x in d[:8])))

# ---------- the record array ---------------------------------------------
print("\n" + "=" * 78)
print("[2] the 0x20-stride record array containing the 4 differing bytes")
print("=" * 78)
BASE = 0x17C50
for i in range(8):
    r = BASE + i * 0x20
    fo = struct.unpack_from(">IIIIIII", cf, r)
    mo = struct.unpack_from(">IIIIIII", merged, r)
    star = "  <== DIFFERS" if fo != mo else ""
    p1c_o = struct.unpack_from(">I", cf, r + 0x1C)[0]
    p1c_m = struct.unpack_from(">I", merged, r + 0x1C)[0]
    print("\n  record @0x%06X%s" % (r, star))
    print("    owner: +00=%08X +04=%08X +08=%08X +18=%08X +1C=%08X"
          % (fo[0], fo[1], fo[2], fo[6], p1c_o))
    print("    oem  : +00=%08X +04=%08X +08=%08X +18=%08X +1C=%08X"
          % (mo[0], mo[1], mo[2], mo[6], p1c_m))

# ---------- what do the changed pointers point at? ----------------------
print("\n" + "=" * 78)
print("[3] the changed pointer targets")
print("=" * 78)
for a, who in ((0x00141C74, "OEM  record[0].+1C"),
               (0x0015BE00, "OWNER record[0].+1C")):
    print("\n  %s -> 0x%06X" % (who, a))
    if a + 32 <= len(cf):
        print("     backup bytes: %s" % cf[a:a + 32].hex())
    if a + 32 <= len(merged):
        print("     oem    bytes: %s" % merged[a:a + 32].hex())
    reg = ("F10A calibration block" if 0x140000 <= a < 0x15BF4C
           else "app" if 0x10000 <= a < 0x140000 else "?")
    print("     region: %s" % reg)

print("\n  0x40007AF9 / 0x40007AFD are SRAM (a per-record status/state byte),")
print("  4 bytes apart - consistent with selecting a different record slot.")

# ---------- do these bytes relate to ANY audited peripheral? ------------
print("\n" + "=" * 78)
print("[4] do the differing bytes touch any pin-related table?")
print("=" * 78)
TABLES = [
    (0x16B28, 0x16E60, "ADC config (header+groups+channels)"),
    (0x17050, 0x171D0, "EIRQ/WKUP config"),
    (0x175D4, 0x17780, "PWM/eMIOS config"),
    (0x11800, 0x11C00, "INTC vector table"),
]
for a in (0x017CAD, 0x017CAE, 0x017CAF, 0x017CBB, 0x13FFFF):
    hit = next((nm for lo, hi, nm in TABLES if lo <= a < hi), None)
    print("  0x%06X : %s" % (a, hit if hit else "NOT in any pin-related table"))
print("\n  => the owner module's differences are calibration-record selection")
print("     plus the integrity byte. None enables or configures a pad.")
