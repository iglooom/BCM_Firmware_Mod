import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# TX descriptor (mirrors copier record): +0x08 frame-image ptr, +0x1a MBidx, +0x1e copymask, +0x1d incr
# MS 0x080 TX = MB index 5. Find TX descriptors with +0x1a == 5 and +8 a RAM frame-image ptr.
print("=== TX descriptors MBidx(+0x1a)==5 (MS 0x080) ===")
for a in range(0x10000,min(0x160000,N)-0x20):
    if u8(a+0x1a)==5:
        fi=u32(a+8); cm=u8(a+0x1e); dlc=u8(a+0x18)
        if 0x40000600<=fi<0x40000E00:
            print(f"  @0x{a:06X} frameimg=0x{fi:08X} copymask=0x{cm:02X}({cm:08b}) +0x18=0x{dlc:02X} +0x1d=0x{u8(a+0x1d):02X}")
