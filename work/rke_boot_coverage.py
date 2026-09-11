"""What of the MCU's flash is NOT covered by the OEM VBF set? + reset/boot analysis.

The merged image starts at 0xC000, so an earlier claim that the image is
"complete, no unmapped region" was only true *within* the merged file. This
checks the real device address map (RM peripheral/memory map) against the VBF
block coverage, then decodes the boot configuration.

SPC560B boot: the BAM (0xFFFFC000, ROM) scans candidate boot sectors for a
Reset Configuration Half Word (RCHW) whose top byte pattern is 0x005A; the
word after it is the application entry address.

Read-only.
"""
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()

# VBF block coverage (from work/build_image.py + vbf_crc_validate output)
BLOCKS = [
    (0x0000C000, 0x00004000, "JV6T-14C095-AB  Cal Data F124"),
    (0x00010000, 0x00000020, "JV6T-14C094-AD  RCHW/header"),
    (0x00010020, 0x0012FFE0, "JV6T-14C094-AD  application"),
    (0x00140000, 0x0001BF4C, "JV6T-14C403-AB  Cal Config F10A"),
]

# SPC560B64 code-flash layout (RM memory map, low blocks)
FLASH_SECTORS = [
    (0x00000000, 0x00008000, "code flash array 0  (boot sectors L0/L1)"),
    (0x00008000, 0x0000C000, "code flash array 0  L2/L3"),
    (0x0000C000, 0x00010000, "code flash array 0  L4/L5"),
    (0x00010000, 0x00018000, "code flash array 0  L6.."),
    (0x00018000, 0x00020000, "code flash array 0"),
    (0x00020000, 0x00040000, "code flash array 0"),
    (0x00040000, 0x00080000, "code flash array 0"),
    (0x00080000, 0x00100000, "code flash array 1"),
    (0x00100000, 0x00180000, "code flash array 2"),
    (0x00200000, 0x00204000, "flash SHADOW array"),
    (0x00800000, 0x00810000, "DATA flash array 0 (EEPROM emulation)"),
    (0xFFFFC000, 0x100000000, "BAM (boot assist ROM, mask ROM)"),
]

covered = []
for a, l, n in BLOCKS:
    covered.append((a, a + l))


def cov(lo, hi):
    """fraction of [lo,hi) covered by VBF blocks"""
    tot = hi - lo
    c = 0
    for s, e in covered:
        c += max(0, min(e, hi) - max(s, lo))
    return c, tot


print("=" * 80)
print("VBF COVERAGE vs DEVICE FLASH MAP")
print("=" * 80)
print("%-34s %-22s %s" % ("device region", "range", "covered by VBFs"))
print("-" * 80)
for lo, hi, name in FLASH_SECTORS:
    c, t = cov(lo, min(hi, 0x1000000))
    if hi > 0x1000000:
        c, t = 0, 0
        status = "NOT FLASHABLE (mask ROM)"
    elif c == 0:
        status = "*** NONE ***"
    elif c == t:
        status = "full"
    else:
        status = "partial %d/%d (0x%X B)" % (c, t, c)
    print("%-34s 0x%06X-0x%06X  %s" % (name, lo, min(hi, 0x1000000) - 1, status))

print("\n" + "=" * 80)
print("UNCOVERED low flash = 0x000000..0x00BFFF  (%d bytes = %d KB)"
      % (0xC000, 0xC000 // 1024))
print("=" * 80)
print("This is the classic SPC560B bootloader/bootblock region and it is NOT in")
print("any of the three VBFs. The merged image simply starts at 0xC000, so every")
print("scan so far was blind to it.")

# ---- RCHW / boot header decode -----------------------------------------
print("\n" + "=" * 80)
print("BOOT HEADER (RCHW) DECODE")
print("=" * 80)
print("BAM scans boot sectors at 0x00000000, 0x00004000, 0x00010000, 0x0001C000,")
print("0x00020000, 0x00030000 for a valid RCHW (halfword with 0x5A in bits 8..15).\n")

for addr in (0x00000000, 0x00004000, 0x00008000, 0x0000C000,
             0x00010000, 0x0001C000, 0x00020000, 0x00030000):
    if addr >= len(raw):
        print("  0x%08X : outside merged image (not in any VBF)" % addr)
        continue
    hw = struct.unpack_from(">H", raw, addr)[0]
    entry = struct.unpack_from(">I", raw, addr + 4)[0]
    tag = "VALID RCHW" if (hw & 0x00FF) == 0x005A else "-"
    print("  0x%08X : halfword=0x%04X  entry=0x%08X  %s" % (addr, hw, entry, tag))
    if (hw & 0x00FF) == 0x005A:
        print("        RCHW bits: SWT=%d WTE=%d PS0=%d VLE=%d"
              % ((hw >> 15) & 1, (hw >> 14) & 1, (hw >> 12) & 1, (hw >> 8) & 1))

print("\nNOTE: 0x10000 is the app's own RCHW block (its own 0x20-byte VBF block).")
print("If low flash 0x0..0xBFFF also holds an RCHW, the BAM would find THAT first")
print("(lowest address wins), i.e. a bootloader runs before the application.")
