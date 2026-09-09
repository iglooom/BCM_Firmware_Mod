import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def issig(v): return 0x40000600<=v<0x40000E00
netrng={"HS":(0x400001A0,0x40000200),"n1":(0x4000022C,0x40000284),"n2":(0x400002E0,0x40000338),
        "n3":(0x40000394,0x400003EC),"n4":(0x40000448,0x400004A0),"MS":(0x400004FC,0x40000554),
        "MSX":(0x40000588,0x400005E0)}
def netof(v):
    for n,(lo,hi) in netrng.items():
        if lo<=v<hi: return n
    return None

# Parse aligned records: [frameObj][spec1][spec2][sigA][sigB], anchored where word0 is a frameObj
# and word3/word4 are sig RAM.
from collections import defaultdict,Counter
recs=[]
a=0x140000
while a<0x15BF00-20:
    fo=u32(a);spec1=u32(a+4);spec2=u32(a+8);sA=u32(a+12);sB=u32(a+16)
    if netof(fo) and issig(sA) and issig(sB):
        recs.append((a,fo,spec1,spec2,sA,sB)); a+=20; continue
    a+=4
print("aligned records:",len(recs))

# frameObj -> spec1>>18 distribution (candidate CAN id)
fo_ids=defaultdict(Counter)
for a,fo,s1,s2,sA,sB in recs:
    cid=s1>>18
    if 0<cid<0x800 and (s1&0x3FFFF)==0:
        fo_ids[fo][cid]+=1
print("\n=== frameObj -> spec1>>18 (clean id<<18 only) ===")
for fo in sorted(fo_ids):
    print(f"  0x{fo:08X} ({netof(fo)}): "+", ".join(f"0x{i:03X}(x{c})" for i,c in fo_ids[fo].most_common(5)))

# Save all aligned records
with open("aligned_records.txt","w") as f:
    for a,fo,s1,s2,sA,sB in recs:
        f.write(f"{a:06X} fo=0x{fo:08X}({netof(fo)}) spec1={s1:08X} spec2={s2:08X} sigA=0x{sA:08X} sigB=0x{sB:08X}\n")
print("saved aligned_records.txt")
