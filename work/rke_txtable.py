import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
def is_img(v): return 0x40000600<=v<0x40000E00
# TX descriptors: the packer FUN_000fc218 uses +8=image ptr, +0x1a=MBidx. Search the descriptor
# zone 0x142000..0x146000 for records where +8 is a frame image and +0x1a is a small MB (0..17).
# These records are 0x14-strided in that zone (we saw 0x142A7C.. earlier with stride 0x14).
# Print records with MBidx(+0x1a) in 0..17 and cluster by MBidx.
from collections import defaultdict
bymb=defaultdict(list)
a=0x142000
while a<0x146000:
    fi=u32(a+8); mb=u8(a+0x1a); cm=u8(a+0x1e)
    if is_img(fi) and mb<=17:
        bymb[mb].append((a,fi,cm))
    a+=4
for mb in sorted(bymb):
    recs=bymb[mb]
    # only show MBs with a coherent cluster (image bytes within one 8-byte frame window)
    imgs=sorted({fi for _,fi,_ in recs})
    span=imgs[-1]-imgs[0]
    if len(recs)>=3 and span<=8:
        print(f"MB{mb}: image window 0x{imgs[0]:08X}..0x{imgs[-1]:08X} ({len(recs)} recs)")
        for a,fi,cm in recs:
            print(f"    @0x{a:06X} img=0x{fi:08X} copymask=0x{cm:02X}")
