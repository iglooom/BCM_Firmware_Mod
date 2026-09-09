import struct
def crc16_ccitt(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc
tests=[("bins/JV6T-14C094-AD_blk0_0x00010020.bin",0xB8F3),
       ("bins/JV6T-14C094-AD_blk1_0x00010000.bin",0x52E7),
       ("bins/JV6T-14C095-AB_blk0_0x0000C000.bin",0x1153),
       ("bins/JV6T-14C403-AB_blk0_0x00140000.bin",0xF29C)]
for fn,exp in tests:
    d=open(fn,'rb').read()
    got=crc16_ccitt(d)
    print(f"{fn.split('/')[-1]:45s} calc=0x{got:04X} expect=0x{exp:04X} {'OK' if got==exp else 'MISMATCH'}")
