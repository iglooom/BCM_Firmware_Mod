"""Check F124/F10A separately for PI15 ADC/GPIO configuration artifacts."""
import struct
from pathlib import Path

ROOT = Path("/home/gl/Projects/ford/BCM/Research")
BLOCKS = {
    "F124 JV6T-14C095-AB": ROOT / "work/bins/JV6T-14C095-AB_blk0_0x0000C000.bin",
    "F10A JV6T-14C403-AB": ROOT / "work/bins/JV6T-14C403-AB_blk0_0x00140000.bin",
    "APP JV6T-14C094-AD": ROOT / "work/bins/JV6T-14C094-AD_blk0_0x00010020.bin",
}

TARGET_WORDS = {
    "PI15 GPDI": 0xC3F9088F,
    "PI15 PCR": 0xC3F9015E,
    "ADC0 CDR55": 0xFFE001DC,
    "ADC0 DMAE": 0xFFE00040,
    "ADC0 DMAR0": 0xFFE00044,
    "ADC0 DMAR1": 0xFFE00048,
    "ADC0 DMAR2": 0xFFE0004C,
    "ADC config header": 0x00016B28,
    "ADC group table": 0x00016B8C,
    "ADC channel table": 0x00016DF4,
}
CHANNEL_RECORDS = {
    "ADC0 channel 55 record": bytes.fromhex("370000000100"),
    "ADC1 channel 55 record": bytes.fromhex("370100000100"),
}
PI15_MASK = 0x00800000


def find_all(data, pattern):
    offsets = []
    start = 0
    while True:
        offset = data.find(pattern, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


for block_name, path in BLOCKS.items():
    data = path.read_bytes()
    print("\n%s: %s (%d bytes)" % (block_name, path.name, len(data)))
    for target_name, value in TARGET_WORDS.items():
        hits = find_all(data, struct.pack(">I", value))
        print("  %-21s 0x%08X count=%-2d %s" %
              (target_name, value, len(hits), [hex(x) for x in hits]))
    for target_name, pattern in CHANNEL_RECORDS.items():
        hits = find_all(data, pattern)
        print("  %-30s count=%-2d %s" % (target_name, len(hits), [hex(x) for x in hits]))
    mask_hits = find_all(data, struct.pack(">I", PI15_MASK))
    print("  raw 0x00800000 words count=%d (not ADC evidence without a driver reference)" %
          len(mask_hits))
