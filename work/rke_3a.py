import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# MS 0x03A TX = filter-list position (hw MB idx). Find it.
base=0x146950; a=base; pos=0; idx=None
while a+8<=N:
    idf=u32(a); flags=u32(a+4)
    if idf==0 and flags==0: break
    if (idf>>18)==0x03A and ((flags>>24)&0xff)==0x08: idx=pos
    a+=12; pos+=1
print("MS 0x03A TX MB index =",idx)
# The 0x3A frame image: find via routing records producing it. CLockCmd is d3, len8 (whole byte).
# Look in aligned_records for MS records whose sigB is an 8-byte frame image; but simpler: the frame
# image for 0x3A. We know 0x80 cluster ~0x8FF..0x960. 0x3A likely adjacent. Find distinct MS TX frames
# by grouping frameObj sigB clusters again but list ALL clusters (any size) with their frameObj.
recs=[]
for line in open("aligned_records.txt"):
    p=line.split()
    fo=int(p[1].split("=")[1].split("(")[0],16); net=p[1].split("(")[1].rstrip(")")
    sA=int(p[4].split("=")[1],16); sB=int(p[5].split("=")[1],16)
    recs.append((fo,net,sA,sB))
from collections import defaultdict
byfo=defaultdict(set)
for fo,net,sA,sB in recs:
    if net=="MS": byfo[fo].add(sB)
print("\nMS frameObj -> sigB min..max (frame image span):")
for fo in sorted(byfo):
    cs=sorted(byfo[fo])
    print(f"  fo=0x{fo:08X}: 0x{cs[0]:08X}..0x{cs[-1]:08X} ({len(cs)} cells)")
