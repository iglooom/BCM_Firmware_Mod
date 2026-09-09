import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

# Known MSX single-bit signal placements from the 24-byte sig-desc table (byte,bitmask):
# From 0x15A930+: sig=byte<<8|bit at w0? Actually the 24-byte recs gave w[0]=00000001..00000910
# meaning (index<<8)|bitmask? Let's re-derive: earlier "known" was my guess. Re-derive properly.
# The 24-byte records at 0x15A920: field before frameObj: w0 example 00000001,00000102,00000204,
# 00000308,00000410,00000508,00000604,00000720,00000840,00000910 => (byteidx<<8)|(1<<bit)? 
# 0x0001=byte0 bit0; 0x0102=byte1 bit1; 0x0204=byte2 bit2; 0x0308=byte3 bit3;0x0410=byte4 bit4;
# 0x0508=byte5 bit3;0x0604=byte6 bit2;0x0720=byte7 bit5;0x0840=byte8 bit6;0x0910=byte9 bit4
# So format = (byteIndex<<8)|bitmask. GOOD. Map sigRAM->(byte,bitmask):
known={}
for a in range(0x15A930,0x15AAA0,24):
    fld=u32(a); sig=u32(a+8) if False else None
# properly walk the 24-byte records: layout [m1][sigRAM][frameObj][handler][?][field]
# From dump: 15A924: 40000B58(sig) 400005A8(fo) 00000000 00000000 00000001(field) then next m1
# so record start ~0x15A920 stride 24: w0=mask(FFF6FAFF) w1=sig w2=fo w3=handler w4=0 w5=field
for a in range(0x15A920,0x15AAB0,24):
    w=[u32(a+4*i) for i in range(6)]
    sig=w[1]; fo=w[2]; field=w[5]
    if 0x40000600<=sig<0x40000E00 and field>>16==0:
        byte=field>>8; bm=field&0xFF
        known[sig]=(byte,bm,a)
print("known MSX bit sigs:")
for s,(b,m,a) in sorted(known.items()):
    print(f"  0x{s:08X} byte{b} mask0x{m:02X}  @{a:06X}")

# Now decode pk2 in 20-byte routing recs for these sigs to learn pk2 encoding
print("\n=== pk2 for known sigs in MSX frame (fo=0x400005A8) ===")
a=0x140000
while a<0x15BF00-20:
    sA=u32(a);sB=u32(a+4);fo=u32(a+8);pk1=u32(a+12);pk2=u32(a+16)
    if fo==0x400005A8 and (sA in known or sB in known):
        s=sA if sA in known else sB
        b,m,_=known[s]
        print(f"  @{a:06X} sigA=0x{sA:08X} sigB=0x{sB:08X} pk1={pk1:08X} pk2={pk2:08X}  known {s:08X}=byte{b} mask{m:02X}")
        a+=20; continue
    a+=4
