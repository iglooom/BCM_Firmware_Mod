import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
# The 24-byte signal-descriptor table from docs is at 0x15A920. Validate stride/extent:
# record: +0x00 mask +0x04 sigRAM +0x08 frameObj +0x0C selector +0x10 0 +0x14 (byteIdx<<8)|bmask
base=0x15A920
print("signal-descriptor table @0x15A920 (first 30 recs):")
good=0
for i in range(400):
    a=base+i*24
    if a+24>N: break
    mask=u32(a);sig=u32(a+4);fo=u32(a+8);sel=u32(a+0xc);z=u32(a+0x10);bf=u32(a+0x14)
    ok = 0x40000600<=sig<0x40000E00 and 0x40000180<=fo<0x40000600 and z==0
    if ok: good=i+1
    if i<30:
        print(f"  #{i:3d}@0x{a:06X} mask=0x{mask:08X} sig=0x{sig:08X} fo=0x{fo:08X} sel=0x{sel:08X} bf=0x{bf:08X} {'OK' if ok else ''}")
print("...\ncontiguous-valid count from start:",good)
# where does it end?
i=0
while True:
    a=base+i*24
    if a+24>N: break
    sig=u32(a+4);fo=u32(a+8);z=u32(a+0x10)
    if not(0x40000600<=sig<0x40000E00 and 0x40000180<=fo<0x40000600 and z==0): break
    i+=1
print(f"table extent: {i} records, 0x{base:06X}..0x{base+i*24:06X}")
