"""Hunt for OUTPUT-driver pins: pads this firmware drives (transistor/relay/MOSFET gates).

Motivation: a BCM drives many low-side transistors, yet the earlier audit found only
five GPDO pads. Either (a) outputs are driven through a path that names no GPDO
address (parallel/masked writes, or eMIOS PWM), or (b) the pad set really is small.

Checks:
  [1] EVERY SIUL pad register present anywhere as a literal, decoded to a pad name:
        PCR   = SIU+0x40+2*pad      (config)
        GPDO  = SIU+0x600+pad       (single-pad output)
        GPDI  = SIU+0x800+pad       (single-pad input)
        PGPDO = SIU+0xC00+2*port    (16 pads at once - writes MANY outputs, names no GPDO)
        PGPDI = SIU+0xC40+2*port
        MPGPDO= SIU+0xC80+4*port    (masked parallel out - same blind spot)
  [2] dump the pad/peripheral descriptor table region so its record layout is explicit
  [3] enumerate eMIOS channels actually referenced (PWM = the usual way to drive a
      MOSFET gate), resolved + indexed, on both modules

Read-only.
"""
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()
SIU = 0xC3F90000
PORT = "ABCDEFGHIJ"


def padname(pad):
    return "P%s%d" % (PORT[pad // 16], pad % 16)


def decode(v):
    o = v - SIU
    if 0x40 <= o < 0x40 + 149 * 2 and o % 2 == 0:
        p = (o - 0x40) // 2
        return "PCR[%d] = %s" % (p, padname(p))
    if 0x600 <= o < 0x6A4:
        p = o - 0x600
        return "GPDO[%d] = %s  (OUTPUT)" % (p, padname(p))
    if 0x800 <= o < 0x8A4:
        p = o - 0x800
        return "GPDI[%d] = %s  (input)" % (p, padname(p))
    if 0xC00 <= o < 0xC14:
        return "PGPDO[port %s]  (PARALLEL OUTPUT)" % PORT[(o - 0xC00) // 2]
    if 0xC40 <= o < 0xC54:
        return "PGPDI[port %s]" % PORT[(o - 0xC40) // 2]
    if 0xC80 <= o < 0xCA8:
        return "MPGPDO[port %s]  (MASKED PARALLEL OUTPUT)" % PORT[(o - 0xC80) // 4]
    return None


print("=" * 78)
print("[1] every SIUL pad register appearing as a 32-bit literal")
print("=" * 78)
found = {}
for i in range(len(raw) - 3):
    v = struct.unpack_from(">I", raw, i)[0]
    if SIU <= v < SIU + 0x1000:
        d = decode(v)
        if d:
            found.setdefault(v, []).append(i)

outs, ins, pcrs, par = [], [], [], []
for v in sorted(found):
    d = decode(v)
    line = "  0x%08X  %-34s @%s" % (v, d, ",".join(hex(o) for o in found[v][:4]))
    print(line)
    if "OUTPUT" in d and "PARALLEL" not in d and "MASKED" not in d:
        outs.append(v - SIU - 0x600)
    elif "(input)" in d:
        ins.append(v - SIU - 0x800)
    elif d.startswith("PCR"):
        pcrs.append((v - SIU - 0x40) // 2)
    else:
        par.append(d)

print("\n  single-pad OUTPUT pads : %s" % ([padname(p) for p in sorted(outs)] or "none"))
print("  single-pad input pads  : %s" % ([padname(p) for p in sorted(ins)] or "none"))
print("  configured PCR pads    : %s" % ([padname(p) for p in sorted(pcrs)] or "none"))
print("  parallel/masked regs   : %s" % (par or "NONE"))
print("\n  >>> If parallel/masked is NONE, firmware cannot be driving a large bank of")
print("      output pads through a path that hides individual GPDO addresses.")

# ---------------- [2] descriptor table ----------------------------------
print("\n" + "=" * 78)
print("[2] pad/peripheral descriptor records")
print("=" * 78)


def u32(o):
    return struct.unpack_from(">I", raw, o)[0]


STARTS = [0x146840, 0x146874, 0x1468A8, 0x1468DC, 0x1AE68]
for s in STARTS:
    print("\n  record @0x%06X" % s)
    for k in range(0, 0x34, 4):
        v = u32(s + k)
        note = decode(v) if SIU <= v < SIU + 0x1000 else ""
        if 0xFFE40000 <= v <= 0xFFE5FFFF:
            note = "LINFlex_%d base" % ((v - 0xFFE40000) // 0x4000)
        elif 0xC3FA0000 <= v < 0xC3FA8000:
            note = "eMIOS_%d base" % ((v - 0xC3FA0000) // 0x4000)
        print("    +0x%02X  0x%08X  %s" % (k, v, note))

# ---------------- [3] eMIOS channels ------------------------------------
print("\n" + "=" * 78)
print("[3] eMIOS channel registers referenced as literals (PWM output candidates)")
print("=" * 78)
for mod, base in (("eMIOS_0", 0xC3FA0000), ("eMIOS_1", 0xC3FA4000)):
    chans = {}
    for i in range(len(raw) - 3):
        v = struct.unpack_from(">I", raw, i)[0]
        if base <= v < base + 0x4000:
            off = v - base
            if off >= 0x20:
                ch = (off - 0x20) // 0x20
                reg = (off - 0x20) % 0x20
                chans.setdefault(ch, []).append((reg, i))
    print("\n  %s @0x%08X : channels referenced = %s"
          % (mod, base, sorted(chans) or "none"))
    for ch in sorted(chans):
        rn = {0: "CADR", 4: "CBDR", 8: "CCNTR", 0xC: "CCR", 0x10: "CSR"}
        regs = sorted({rn.get(r, "+0x%X" % r) for r, _ in chans[ch]})
        print("     ch%-3d %s" % (ch, ",".join(regs)))
