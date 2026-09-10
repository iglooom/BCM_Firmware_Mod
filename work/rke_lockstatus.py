import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# MS-CAN TX frame 0x080 (BCM-composed central-lock status frame). Find its TX MB index & frame image.
# MS filter list @0x146950, 12B recs. Find id 0x080 TX position.
base=0x146950
a=base; idx=None; pos=0
while a+12<=N:
    idf=u32(a); flags=u32(a+4)
    if idf==0 and flags==0: break
    if (idf>>18)==0x080 and ((flags>>24)&0xff)==0x08:
        idx=pos
    a+=12; pos+=1
print("MS 0x080 TX filter-list position (hw MB idx) =",idx)
# find its frame-image via TX descriptor OR reuse the 28B copier-record scan for MBidx==idx (TX packer records)
if idx is not None:
    print(f"\n28B records with MBidx==0x{idx:02X}:")
    for a in range(0x10000,min(0x160000,N)-28):
        if u8(a+0x19)==idx:
            dest=u32(a);dlc=u8(a+0x18);mask=u8(a+0x1a);sf=u32(a+8)
            if 0x40000600<=dest<0x40000E00 and 1<=dlc<=8:
                print(f"  @0x{a:06X} img=0x{dest:08X} DLC={dlc} mask=0x{mask:02X}({mask:08b}) sf=0x{sf:08X}")
