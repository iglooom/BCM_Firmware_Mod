import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]

# Find MS 0x080 TX frame-image base. TX frames are packed by FUN_000fc218/2f6 from a frame image.
# The frame image address is stored in a TX descriptor; but simplest: TX frame images for MS live in RAM.
# Approach: parse aligned_records, for MS-net TX composition the sigB (dest) is the frame image.
# We know PowerMode is d2 of 0x080 and value 6 when ign on. The signal cell (sigA) feeding it is what we want.
#
# Instead of guessing the 0x080 image, find candidate frame-image bases by locating a 28B copier-style TX
# record OR by scanning routing records grouped by a contiguous 8-byte dest span typical of one frame.
#
# We'll enumerate all records and group sigB by 8-byte-aligned frame windows, printing groups whose
# window looks like an 8-byte TX frame image with ~ several signals.
recs=[]
for line in open("aligned_records.txt"):
    p=line.split()
    fo=int(p[1].split("=")[1].split("(")[0],16); net=p[1].split("(")[1].rstrip(")")
    sA=int(p[4].split("=")[1],16); sB=int(p[5].split("=")[1],16)
    recs.append((fo,net,sA,sB))

# Frame images are RAM regions written by TX packers. We separately need the MS 0x080 image.
# Let me find it from the net's TX descriptor table instead: MS ctrlDesc @0x146900, +0x20 = runtime block 0x40000638.
# TX frames images are usually a distinct contiguous block. Print the distinct sigB values on MS net sorted.
ms_sb=sorted({sB for fo,net,sA,sB in recs if net=="MS"})
print("MS net distinct sigB (TX dest / normalized cells):")
# cluster contiguous
clusters=[]
cur=[ms_sb[0]]
for v in ms_sb[1:]:
    if v-cur[-1]<=2: cur.append(v)
    else: clusters.append(cur); cur=[v]
clusters.append(cur)
for c in clusters:
    print(f"  0x{c[0]:08X}..0x{c[-1]:08X}  ({len(c)} cells)")
