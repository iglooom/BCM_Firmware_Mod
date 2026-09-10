import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
# From aligned_records.txt: [frameObj][spec1][spec2][sigA][sigB]. TX packing: sigA=signal cell -> sigB=TX frame image.
# Find the MS 0x080 TX frame image page. TX frame images live in a different RAM band than RX (0x40000918 was RX).
# Approach: list all distinct frameObj values on the MS net and the sig cells they touch, to locate the lock-status frame.
recs=[]
for line in open("aligned_records.txt"):
    # format: ADDR fo=0x..(NET) spec1=.. spec2=.. sigA=0x.. sigB=0x..
    parts=line.split()
    addr=int(parts[0],16)
    fo=int(parts[1].split("=")[1].split("(")[0],16)
    net=parts[1].split("(")[1].rstrip(")")
    sigA=int(parts[4].split("=")[1],16)
    sigB=int(parts[5].split("=")[1],16)
    recs.append((addr,fo,net,sigA,sigB))
# MS frameObjs
ms=[r for r in recs if r[2]=="MS"]
from collections import defaultdict
byfo=defaultdict(list)
for a,fo,net,sA,sB in ms: byfo[fo].append((a,sA,sB))
print(f"MS-net records: {len(ms)}, distinct frameObj: {len(byfo)}")
for fo in sorted(byfo):
    cells=byfo[fo]
    sags=sorted({s for _,s,_ in cells}); sbgs=sorted({s for _,_,s in cells})
    print(f"\nframeObj 0x{fo:08X}: {len(cells)} recs")
    print(f"   sigA span: 0x{min(sags):08X}..0x{max(sags):08X}   sigB span: 0x{min(sbgs):08X}..0x{max(sbgs):08X}")
