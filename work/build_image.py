#!/usr/bin/env python3
# Build one flat flash image for the MPC5607B address space (base 0x0).
import struct

regions = [
    (0x0000C000, "bins/JV6T-14C095-AB_blk0_0x0000C000.bin"),  # Cal Data F124
    (0x00010000, "bins/JV6T-14C094-AD_blk1_0x00010000.bin"),  # main RCHW/header
    (0x00010020, "bins/JV6T-14C094-AD_blk0_0x00010020.bin"),  # main application
    (0x00140000, "bins/JV6T-14C403-AB_blk0_0x00140000.bin"),  # Cal Config F10A
]

end = 0
segs = []
for addr, fn in regions:
    d = open(fn, 'rb').read()
    segs.append((addr, d))
    end = max(end, addr + len(d))

img = bytearray(b'\xFF' * end)   # erased-flash fill
for addr, d in segs:
    img[addr:addr+len(d)] = d

open("flash_merged.bin", "wb").write(img)
print(f"merged size = 0x{end:08X} ({end} bytes)")
for addr, d in segs:
    print(f"  0x{addr:08X} .. 0x{addr+len(d)-1:08X}  ({len(d)} bytes)")
