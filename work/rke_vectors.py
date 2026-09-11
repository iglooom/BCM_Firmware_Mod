"""Final boot closure: does ANY interrupt vector point into the un-flashed low flash?

INTC IACKR is programmed to 0x00011800 (FUN_0003594e), i.e. the interrupt vector
table lives at 0x11800 - inside the application block. In software-vector mode the
INTC supplies a 4-byte-per-source table of handler addresses.

If every vector points into the app (>=0xC000), then even interrupts cannot reach
code in the un-flashed 0x0..0xBFFF region, and the application is fully
self-contained at runtime regardless of what a bootloader holds.

Also dumps the bootloader-identification strings found in the app block.

Read-only.
"""
import re
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()

VTAB = 0x00011800
N = 256          # SPC560B64 has ~230 interrupt sources
APP_LO = 0x0000C000

print("=" * 78)
print("INTERRUPT VECTOR TABLE @0x%06X (from INTC IACKR)" % VTAB)
print("=" * 78)
print("NOTE: the entries are NOT addresses - they are VLE `e_b` INSTRUCTIONS")
print("      (opcode 0x78xxxxxx), i.e. a branch table. Decode each one:")
print("      e_b: target = PC + sign_extend(BD24 << 1), BD24 = bits 7..30.\n")


def decode_eb(word, pc):
    """Decode a VLE e_b/e_bl at address pc. Returns (target, is_link) or None."""
    if (word >> 26) != 0x1E:          # 011110 = e_b / e_bl
        return None
    lk = word & 1
    bd24 = (word >> 1) & 0xFFFFFF     # bits 7..30
    if bd24 & 0x800000:               # sign extend 24-bit
        bd24 -= 0x1000000
    return (pc + (bd24 << 1)) & 0xFFFFFFFF, lk


low, app, notbranch, zero = [], 0, [], 0
targets = []
for i in range(N):
    o = VTAB + i * 4
    if o + 4 > len(raw):
        break
    v = struct.unpack_from(">I", raw, o)[0]
    if v in (0, 0xFFFFFFFF):
        zero += 1
        continue
    d = decode_eb(v, o)
    if d is None:
        notbranch.append((i, v))
        continue
    tgt, lk = d
    targets.append((i, v, tgt))
    if tgt < APP_LO:
        low.append((i, tgt))
    else:
        app += 1

print("  vectors examined       : %d" % N)
print("  decoded as e_b/e_bl    : %d" % len(targets))
print("  not a branch           : %d" % len(notbranch))
print("  -> target in app       : %d" % app)
print("  -> target in low flash : %d   %s"
      % (len(low), "*** WOULD BE A PROBLEM ***" if low else "(none)"))
print("  empty/0xFFFFFFFF       : %d" % zero)
for i, t in low[:20]:
    print("     vector %3d -> 0x%08X" % (i, t))
for i, v in notbranch[:10]:
    print("     vector %3d raw 0x%08X (not a branch)" % (i, v))

print("\n  sample of decoded vectors:")
for i, v, t in targets[:12]:
    print("     vector %3d  word 0x%08X  -> 0x%08X" % (i, v, t))

print("\n" + "=" * 78)
print("BOOTLOADER IDENTIFICATION STRINGS (in the APP block)")
print("=" * 78)
for m in re.finditer(rb"[ -~]{10,}", raw[0x13000:0x14000]):
    s = m.group().decode("latin1")
    if any(k in s for k in ("BL", "DS-", "@(#)", "JV6T", "14A")):
        print("  0x%06X  %s" % (0x13000 + m.start(), s))

print("\n  '@(#)' is the classic SCCS 'what' marker; 'BL<date>.<time>.v<ver>' are")
print("  BOOTLOADER version records the app reports (e.g. over UDS DIDs).")
print("  Their presence in the app block is evidence a separate bootloader EXISTS")
print("  in the un-flashed low 48 KB - the app merely knows its version.")
