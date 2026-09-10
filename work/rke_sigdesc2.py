import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
# 24-byte signal descriptor: +0x00 mask +0x04 sigRAM +0x08 frameObj +0x0C handler/selector +0x10 0 +0x14 (byteIdx<<8)|bitmask
# Scan a WIDE range for the table(s) and report any descriptor whose sigRAM is in the MS 0x100/0x80 cluster.
lo,hi=0x159000,min(0x15C000,N-24)
print("=== 24B signal descriptors with sigRAM in 0x400008F0..0x40000960 ===")
a=0x140000
cnt=0
while a<min(0x15C000,N-24):
    sig=u32(a+4); fo=u32(a+8); sel=u32(a+0xc); z=u32(a+0x10); bf=u32(a+0x14); mask=u32(a)
    if 0x400008F0<=sig<0x40000960 and 0x40000180<=fo<0x40000600 and z==0 and bf!=0 and (bf>>16)==0:
        bidx=(bf>>8)&0xFF; bm=bf&0xFF
        print(f"@0x{a:06X} sigRAM=0x{sig:08X} fo=0x{fo:08X} sel/handler=0x{sel:08X} mask=0x{mask:08X} byte{bidx} bmask0x{bm:02X}")
        cnt+=1
    a+=4
print("count:",cnt)
