import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
# 24-byte signal descriptor: +0x00 mask +0x04 sigRAM +0x08 frameObj +0x0C handler +0x10 0 +0x14 (byteIdx<<8)|bitmask
# Find table extent by scanning where records look valid, across 0x159000..0x15C000
MSfo={0x400004FD,0x400004FE,0x400004FF}
lo,hi=0x158000,min(0x15C000,N-24)
print("=== 24-byte signal descriptors for MS 0x100 frameObjs (0x4FD/4FE/4FF) ===")
a=lo
while a<hi:
    mask=u32(a); sig=u32(a+4); fo=u32(a+8); h=u32(a+0xc); z=u32(a+0x10); bf=u32(a+0x14)
    if fo in MSfo and 0x40000600<=sig<0x40000E00:
        bidx=(bf>>8)&0xFFFF; bmask=bf&0xFF
        print(f"@0x{a:06X} fo=0x{fo:08X} sigRAM=0x{sig:08X} mask=0x{mask:08X} bf=0x{bf:08X} byte{bidx} bmask0x{bmask:02X} h=0x{h:08X}")
    a+=4
print("\n=== ALL byte-index-7 descriptors anywhere (dest sig cells) ===")
a=lo
while a<hi:
    sig=u32(a+4); fo=u32(a+8); bf=u32(a+0x14); z=u32(a+0x10)
    if 0x40000600<=sig<0x40000E00 and 0x40000180<=fo<0x40000600 and z==0 and ((bf>>8)&0xFFFF)==7 and 0<(bf&0xFF)<=0xFF:
        print(f"@0x{a:06X} fo=0x{fo:08X} sigRAM=0x{sig:08X} bf=0x{bf:08X} bmask0x{bf&0xFF:02X}")
    a+=4
