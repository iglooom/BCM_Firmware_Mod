import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# 32-byte reception descriptor: +0x08 MBbit, +0x0C handler->routing rec, +0x18 frame-image RAM.
# MS 0x100 image base = 0x40000918. Find 32B descriptors whose +0x18 in [0x918..0x91F].
print("=== 32B reception descriptors -> 0x100 MS image (0x40000918..1F) ===")
for a in range(0x10000,N-0x20,4):
    im=u32(a+0x18); hp=u32(a+0x0C); mb=u32(a+0x08)
    if 0x40000918<=im<=0x4000091F and 0x140000<=hp<0x160000 and bin(mb).count("1")==1:
        print("  @0x%06X MBbit=0x%08X handler->0x%06X image=0x%08X"%(a,mb,hp,im))
