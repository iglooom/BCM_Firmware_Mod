import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# Approach: the TX packer reads descriptor+8 = frame image, +0x1a = MBidx. For MS 0x080 = MB5.
# But +0x1a==5 is noisy. Constrain: a genuine TX descriptor record is 0x14-byte-strided in the
# routing/descriptor region and its +0x08 points to an 8-byte-aligned-ish frame image reused across
# ~8 records (one per signal). Find frame-image bases that appear with MBidx==5 in MANY records.
from collections import Counter
c=Counter()
detail={}
for a in range(0x142000,0x145000):  # MS TX descriptor zone (near 0x142A7C seen earlier)
    if u8(a+0x1a)==5:
        fi=u32(a+8)
        if 0x400008F0<=fi<0x40000960:  # plausible 0x80 image window
            base=fi & ~0xF
            c[base]+=1
            detail.setdefault(fi,0)
            detail[fi]+=1
print("frame-image bytes seen with MBidx==5 in MS TX zone (0x142000-0x145000):")
for fi in sorted(detail):
    print(f"  0x{fi:08X} x{detail[fi]}  (d-index if base 0x400008FF: {fi-0x400008FF})")
