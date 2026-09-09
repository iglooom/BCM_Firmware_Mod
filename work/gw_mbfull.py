import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

# MB filter lists: 12-byte records [id<<18][flags][mask]. Parse until it stops looking valid.
# HS list starts 0x146530 ; MS list starts 0x146950 ; MSX 0x146CA0
def parse(name, start, stop):
    print(f"\n===== {name} MB list @0x{start:06X} =====")
    rx=[]; tx=[]; other=[]
    a=start
    while a < stop:
        w0=u32(a); w1=u32(a+4); w2=u32(a+8)
        idv = w0>>18
        flag = (w1>>24)&0xFF
        # validity: id<<18 means low 18 bits zero, id<=0x7FF
        if (w0 & 0x3FFFF)==0 and 0 < (w0>>18) <= 0x7FF:
            dirn = "RX" if flag==0x04 else ("TX" if flag==0x08 else f"?{flag:02X}")
            print(f"  @0x{a:06X}: id=0x{idv:03X} flags=0x{w1:08X} mask=0x{w2:08X} [{dirn}]")
            if flag==0x04: rx.append(idv)
            elif flag==0x08: tx.append(idv)
            else: other.append((idv,flag))
            a+=12
        else:
            # try: maybe end of list / different record. stop scanning contiguous
            break
    print(f"  -> RX({len(rx)}): "+", ".join(f"0x{x:03X}" for x in sorted(set(rx))))
    print(f"  -> TX({len(tx)}): "+", ".join(f"0x{x:03X}" for x in sorted(set(tx))))
    if other: print("  -> other:",other)
    return sorted(set(rx)), sorted(set(tx))

hs = parse("HS-CAN", 0x146530, 0x146900)
ms = parse("MS-CAN", 0x146950, 0x146C50)
