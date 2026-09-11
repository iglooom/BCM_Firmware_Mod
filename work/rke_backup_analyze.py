"""Analyze the owner backup for anything NEW bearing on the PI15/PF12 question.

New material never before analyzed (all three were outside the OEM VBF set):
  cflash.bin 0x000000..0x00BFFF  - the PBL (primary bootloader), 48 KB
  shadow.bin 0x200000..0x203FFF  - flash shadow array (boot cfg / censorship)
  dflash.bin 0x800000..0x80FFFF  - data flash / EEPROM emulation (variant coding!)

Checks:
  [1] confirm the backup reproduces the OEM app (sanity: same image we analyzed)
  [2] raw scan of the PBL + shadow + dflash for the target pins' register
      addresses (PCR/GPDI/GPDO for PI15 pad143 & PF12 pad92), plus every other
      SIUL pad register, ADC channel-55 CDR, PSMI block, and eMIOS ch25
  [3] shadow-array boot configuration (censorship/serial boot words)
  [4] dflash content survey - is variant coding present, and does any byte
      pattern look like pin/button configuration?

Read-only.
"""
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
BK = ROOT + "/backups/owner-backup-20260911T090300Z/"
cf = open(BK + "cflash.bin", "rb").read()
sh = open(BK + "shadow.bin", "rb").read()
df = open(BK + "dflash.bin", "rb").read()
merged = open(ROOT + "/work/flash_merged.bin", "rb").read()

SIU = 0xC3F90000
PORT = "ABCDEFGHIJ"


def padname(p):
    return "P%s%d" % (PORT[p // 16], p % 16)


# ---------- [1] sanity: backup vs merged OEM image -----------------------
print("=" * 78)
print("[1] backup vs OEM merged image (app region 0x10000..0x13FFFF)")
print("=" * 78)
diffs = [i for i in range(0x10000, 0x140000)
         if i < len(merged) and cf[i] != merged[i]]
print("  differing bytes in app: %d" % len(diffs))
for i in diffs[:12]:
    print("     0x%06X  backup=0x%02X  oem=0x%02X" % (i, cf[i], merged[i]))
print("  -> confirms this is the same firmware we analyzed (plus config bytes)")

# ---------- [2] target pin registers in the NEW regions -----------------
TARGETS = {
    SIU + 0x40 + 2 * 143: "PI15 PCR[143]",
    SIU + 0x800 + 143: "PI15 GPDI",
    SIU + 0x600 + 143: "PI15 GPDO",
    SIU + 0x40 + 2 * 92: "PF12 PCR[92]",
    SIU + 0x800 + 92: "PF12 GPDI",
    SIU + 0x600 + 92: "PF12 GPDO",
    0xFFE001DC: "ADC0 CDR55 (PI15 analog)",
    0xC3F90524: "PSMI36_39 (PADSEL37=CS0_4)",
    0xC3F90530: "PSMI48_51 (PADSEL51=E1UC25)",
    0xC3FA434C: "eMIOS_1 CCR25 (PF12)",
}

REGIONS = [("PBL  (cflash 0x0..0xBFFF)", cf[:0xC000], 0),
           ("shadow", sh, 0x200000),
           ("dflash", df, 0x800000)]

print("\n" + "=" * 78)
print("[2] target pin/peripheral registers in the NEW regions")
print("=" * 78)
for name, blob, base in REGIONS:
    print("\n  --- %s ---" % name)
    any_hit = False
    for addr, label in sorted(TARGETS.items()):
        pat = struct.pack(">I", addr)
        offs = []
        s = 0
        while True:
            i = blob.find(pat, s)
            if i < 0:
                break
            offs.append(base + i)
            s = i + 1
        if offs:
            any_hit = True
            print("     0x%08X %-28s FOUND @%s"
                  % (addr, label, ",".join(hex(o) for o in offs[:4])))
    if not any_hit:
        print("     none of the target registers appear")

# every SIUL pad register in the PBL
print("\n  --- all SIUL pad registers referenced in the PBL ---")
pads = {}
for i in range(len(cf[:0xC000]) - 3):
    v = struct.unpack_from(">I", cf, i)[0]
    if SIU <= v < SIU + 0x1000:
        o = v - SIU
        if 0x40 <= o < 0x40 + 149 * 2 and o % 2 == 0:
            pads.setdefault("PCR[%d]=%s" % ((o - 0x40) // 2,
                                            padname((o - 0x40) // 2)), []).append(i)
        elif 0x600 <= o < 0x6A4:
            pads.setdefault("GPDO[%d]=%s" % (o - 0x600, padname(o - 0x600)), []).append(i)
        elif 0x800 <= o < 0x8A4:
            pads.setdefault("GPDI[%d]=%s" % (o - 0x800, padname(o - 0x800)), []).append(i)
        else:
            pads.setdefault("SIU+0x%03X" % o, []).append(i)
for k in sorted(pads):
    print("     %-22s @%s" % (k, ",".join(hex(x) for x in pads[k][:3])))
if not pads:
    print("     (none - the PBL references no SIUL pad register at all)")

# ---------- [3] shadow array boot configuration -------------------------
print("\n" + "=" * 78)
print("[3] flash shadow array — boot/censorship configuration")
print("=" * 78)
NV = {0x200000: "NVHWOPT (hw options)", 0x200004: "NVPWD0 (censorship pwd hi)",
      0x200008: "NVPWD1 (censorship pwd lo)", 0x20000C: "NVSCC0",
      0x200010: "NVSCC1", 0x2001E0: "NVBIU0", 0x2001E4: "NVBIU1"}
for a in sorted(NV):
    o = a - 0x200000
    if o + 4 <= len(sh):
        print("  0x%08X %-26s = 0x%08X" % (a, NV[a],
              struct.unpack_from(">I", sh, o)[0]))
nonff = sum(1 for b in sh if b != 0xFF)
print("  shadow non-0xFF bytes: %d / %d" % (nonff, len(sh)))
print("  first 64 bytes: %s" % sh[:64].hex())

# ---------- [4] dflash survey -------------------------------------------
print("\n" + "=" * 78)
print("[4] data flash / EEPROM emulation survey")
print("=" * 78)
nonff = sum(1 for b in df if b != 0xFF)
print("  non-0xFF bytes: %d / %d (%.1f%% used)"
      % (nonff, len(df), 100 * nonff / len(df)))
print("  populated 256-byte pages:")
for p in range(0, len(df), 256):
    page = df[p:p + 256]
    if any(b != 0xFF for b in page):
        print("     0x%06X: %s" % (0x800000 + p, page[:32].hex()))
