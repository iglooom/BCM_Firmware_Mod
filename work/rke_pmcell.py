import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
# aligned records: [frameObj][spec1][spec2][sigA][sigB]. spec2 high byte = bitmask in target byte.
# PowerMode = d2 bits3..7 => mask 0xF8 (len5 at bit3). Also d5 mirror = same 0xF8. UB bits single.
# Search MS-net records with bitmask 0xF8.
recs=[]
for line in open("aligned_records.txt"):
    p=line.split()
    addr=int(p[0],16)
    fo=int(p[1].split("=")[1].split("(")[0],16); net=p[1].split("(")[1].rstrip(")")
    s1=int(p[2].split("=")[1],16); s2=int(p[3].split("=")[1],16)
    sA=int(p[4].split("=")[1],16); sB=int(p[5].split("=")[1],16)
    recs.append((addr,fo,net,s1,s2,sA,sB))

print("=== MS records with spec2 bitmask 0xF8 (len-5 field, PowerMode candidate) ===")
for addr,fo,net,s1,s2,sA,sB in recs:
    if net=="MS" and ((s2>>24)&0xFF)==0xF8:
        print(f"@0x{addr:06X} fo=0x{fo:08X} spec1=0x{s1:08X} spec2=0x{s2:08X} sigA=0x{sA:08X} sigB=0x{sB:08X}")

# Also: build frameObj -> set of sigB (frame-image bytes) to identify the 0x80 image cluster (8 contiguous)
from collections import defaultdict
byfo=defaultdict(set)
for addr,fo,net,s1,s2,sA,sB in recs:
    if net=="MS": byfo[fo].add(sB)
print("\n=== MS frameObj sigB clusters (candidate TX frame images, size>=5 contiguous) ===")
for fo,cells in byfo.items():
    cs=sorted(cells)
    # find contiguous runs
    run=[cs[0]]
    for v in cs[1:]:
        if v-run[-1]==1: run.append(v)
        else:
            if len(run)>=5: print(f"  fo=0x{fo:08X} image 0x{run[0]:08X}..0x{run[-1]:08X} ({len(run)}B)")
            run=[v]
    if len(run)>=5: print(f"  fo=0x{fo:08X} image 0x{run[0]:08X}..0x{run[-1]:08X} ({len(run)}B)")
