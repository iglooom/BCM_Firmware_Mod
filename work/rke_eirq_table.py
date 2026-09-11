"""Decode the generic external-interrupt / wakeup configuration table used by
FUN_0003c4cc -> FUN_0003c88c on the BCM image.

Layout (from the decompiled driver):
  header @DAT_00017050 : [0] u8 count, [+4] u32 pointer to record array
  record : 32 bytes; [0] u8 source id, [+4] u32 flags, [+0xC] u32 mode

Source id decoding (FUN_0003c88c):
  id <  0x40 : peripheral block at 0xC3FA_0000 / 0xC3FA_3C00 (SIUL-external / INTC-ish)
  0x40..0x57 : SIUL EIRQ channel  = id - 0x40
  id >= 0x58 : WKPU wakeup channel = id - 0x58

Flags bits used by the driver: bit0 = filter enable (WIFER), bit1 = pullup (WIPUER),
bit7 = rising edge, bit8 = both/level.

Read-only.
"""
import struct

IMG = "/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin"
HDR = 0x17050          # DAT_00017050, file offset == memory address in this image
img = open(IMG, "rb").read()

# WKUP channel -> pad, from SPC560B64 ref-manual wakeup-source table (pages 268-270)
WKUP_PAD = {
    0: "API (internal)", 1: "RTC (internal)", 2: "PA1 (PCR1, NMI)", 3: "PA2 (PCR2)",
    4: "PB1 (PCR17, CAN0RX/LIN0RX)", 5: "PC11 (PCR43, CAN1RX/CAN4RX)",
    6: "PE0 (PCR64, CAN5RX)", 7: "PE9 (PCR73, CAN2RX/CAN3RX)", 8: "PB10 (PCR26)",
    9: "PA4 (PCR4, LIN5RX)", 10: "PA15 (PCR15)", 11: "PB3 (PCR19, LIN0RX)",
    12: "PC7 (PCR39, LIN1RX)", 13: "PC9 (PCR41, LIN2RX)", 14: "PE11 (PCR75, LIN3RX)",
    15: "PF11 (PCR91, LIN4RX)", 16: "PF13 (PCR93, LIN5RX)", 17: "PG3 (PCR99)",
    18: "PG5 (PCR101)", 19: "PA0 (PCR0)", 20: "PG7 (PCR103, LIN6RX)",
    21: "PG9 (PCR105, LIN7RX)", 22: "PF9 (PCR89, CAN2RX/CAN3RX)",
    23: "PI3 (PCR131, LIN9RX)", 24: "PI1 (PCR129, LIN8RX)", 25: "PB8 (PCR24)",
    26: "PB9 (PCR25)", 27: "PD0 (PCR48)", 28: "PD1 (PCR49)",
}


def u32(off):
    return struct.unpack_from(">I", img, off)[0]


count = img[HDR]
recs = u32(HDR + 4)
print("config header @0x%06X : count=%d  records@0x%06X (32 B each)" % (HDR, count, recs))
print()
print("%-4s %-6s %-28s %-10s %-6s %s" % ("idx", "srcid", "route", "flags", "mode", "edge/opts"))
print("-" * 92)

wk_used, eirq_used = [], []
for i in range(count):
    r = recs + i * 32
    sid = img[r]
    flags = u32(r + 4)
    mode = u32(r + 0xC)
    if sid < 0x40:
        route = "periph 0xC3FA_xxxx blk %d" % sid
    elif sid < 0x58:
        ch = sid - 0x40
        eirq_used.append(ch)
        route = "SIUL EIRQ%d" % ch
    else:
        ch = sid - 0x58
        wk_used.append(ch)
        route = "WKUP%d = %s" % (ch, WKUP_PAD.get(ch, "?"))
    opts = []
    if flags & 0x100:
        opts.append("both/level")
    elif flags & 0x80:
        opts.append("rising")
    else:
        opts.append("falling")
    if flags & 1:
        opts.append("filter")
    if flags & 2:
        opts.append("pullup")
    print("%-4d 0x%02X   %-28s 0x%08X %-6d %s" % (i, sid, route, flags, mode, ",".join(opts)))

print()
print("EIRQ channels armed : %s" % (sorted(set(eirq_used)) or "none"))
print("WKUP channels armed : %s" % (sorted(set(wk_used)) or "none"))
print()
print("PI15 / PF12 are absent from the ref-manual WKUP source table entirely,")
print("so no record here can route them regardless of configuration.")
