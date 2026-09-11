"""Decode the CTU event configuration actually programmed by FUN_0003a402.

CRITICAL SUBTLETY (do not misread this): in the ADC init,

    uVar2   = *(ushort*)(group[+0x20])          <- EVENT INDEX (0..63)
    puVar10 = uVar2*4 + 0xFFE64030              <- &CTU_EVTCFGR[uVar2]
    *puVar10 = chan | 0x8000                    <- TM=1, CHANNEL_VALUE=chan
    if (uVar2 == 0x17) EVTCFGR23 |= 0x4000
    if (uVar2 == 0x37) EVTCFGR55 |= 0x4000      <- 0x37 is an EVENT index!

So the literal `0x37` (=55) compared in the code is the **CTU event number**,
NOT the ADC channel number. It is a coincidence that PI15's absolute channel is
also 55. The ADC channel that each event converts is CHANNEL_VALUE, taken from:

    pbVar4 = *(byte**)(group[+0x04])            <- channel-index list
    idx    = *pbVar4
    chan   = channel_cfg[idx].channel           <- 6-byte records @0x16DF4

CTU_EVTCFGR bit layout (RM p817, 16-bit): TM=15, CLR_FLAG=14, ADC_SEL=7,
CHANNEL_VALUE=bits 6..0 (valid 0..95).

This script decodes every group record and reports the real CHANNEL_VALUE.
Read-only.
"""
import struct

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()
u = struct.unpack_from

CONFIG = 0x16B28
GROUP_CFG, N_GROUPS, STRIDE = 0x16B8C, 7, 0x58
CHAN_CFG, N_CHANS = 0x16DF4, 15
PI15_CH = 55


def sig(ch):
    if ch < 16:
        return "ADC0_P[%d]" % ch
    if 32 <= ch < 60:
        return "ADC0_S[%d]" % (ch - 32)
    if 64 <= ch < 68:
        return "ADC0_X[%d]" % (ch - 64)
    return "ch%d" % ch


chan_recs = []
for i in range(N_CHANS):
    o = CHAN_CFG + i * 6
    ch, unit = u(">BB", raw, o)
    chan_recs.append((ch, unit))

print("=" * 78)
print("CTU event configuration decoded from FUN_0003a402")
print("  reminder: `== 0x37` in the code is an EVENT index, not ADC channel 55")
print("=" * 78)

used_channels = set()
for g in range(N_GROUPS):
    r = GROUP_CFG + g * STRIDE
    mode = raw[r + 2]
    chanlist_ptr = u(">I", raw, r + 4)[0]
    evt_ptr = u(">I", raw, r + 0x20)[0]
    print("\n  group[%d] @0x%X  mode_byte=%d" % (g, r, mode))
    print("    +0x04 channel-index list ptr = 0x%08X" % chanlist_ptr)
    print("    +0x20 event-index ptr        = 0x%08X" % evt_ptr)

    if not (0 <= evt_ptr < len(raw)) or evt_ptr == 0:
        print("    -> no CTU event record (ptr out of image / null)")
        continue
    evt = u(">H", raw, evt_ptr)[0]
    if not (0 <= chanlist_ptr < len(raw)) or chanlist_ptr == 0:
        print("    -> event %d but channel list ptr invalid" % evt)
        continue
    idx = raw[chanlist_ptr]
    if idx >= len(chan_recs):
        print("    -> channel index %d out of range" % idx)
        continue
    ch, unit = chan_recs[idx]
    used_channels.add(ch)
    evtaddr = 0xFFE64030 + evt * 4
    print("    EVENT index = %d (0x%X)  -> CTU_EVTCFGR%d @0x%08X"
          % (evt, evt, evt, evtaddr))
    print("    channel-index %d -> channel_cfg[%d] = ADC%d channel %d (%s)"
          % (idx, idx, unit, ch, sig(ch)))
    print("    writes CHANNEL_VALUE=%d, TM=1 (0x%04X)" % (ch, ch | 0x8000))
    if ch == PI15_CH:
        print("    *** THIS EVENT CONVERTS PI15 ***")

print("\n" + "=" * 78)
print("ADC channels reachable via CTU events: %s" % sorted(used_channels))
print("channel %d (PI15 = ADC0_S[23]) triggered by CTU: %s"
      % (PI15_CH, PI15_CH in used_channels))
print("=" * 78)
print("\nNote: CHANNEL_VALUE always comes from the 6-byte channel_cfg records,")
print("whose full channel set is ADC0 {35,42,47,48,58,59} / ADC1 {0,1,2,4,5,8,12,13,38}.")
print("Channel 55 is absent from that table, so no CTU event can name it.")
