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

# Collect: for each frameObj, the set of signalRAM it binds (sigA and/or sigB when in sig range)
from collections import defaultdict
fo_sigs=defaultdict(set)   # frameObj -> {sig: [addr,...]}
fo_sig_loc=defaultdict(lambda: defaultdict(list))
a=0x140000
recs=[]
while a<0x15BF00-20:
    sA=u32(a);sB=u32(a+4);fo=u32(a+8);pk1=u32(a+12);pk2=u32(a+16)
    if netof(fo) and (issig(sA) or issig(sB)):
        recs.append((a,fo,sA,sB,pk1,pk2))
        for s in (sA,sB):
            if issig(s):
                fo_sigs[fo].add(s); fo_sig_loc[fo][s].append(a)
        a+=20; continue
    a+=4

# separate HS frameObjs and MS frameObjs
hs_fo=[fo for fo in fo_sigs if netof(fo)=="HS"]
ms_fo=[fo for fo in fo_sigs if netof(fo)=="MS"]
msx_fo=[fo for fo in fo_sigs if netof(fo)=="MSX"]
print("HS frameObjs:", " ".join("0x%08X"%x for x in sorted(hs_fo)))
print("MS frameObjs:", " ".join("0x%08X"%x for x in sorted(ms_fo)))
print("MSX frameObjs:", " ".join("0x%08X"%x for x in sorted(msx_fo)))

# For each MS frameObj, find signals shared with any HS frameObj (=gateway HS->MS)
print("\n=== signals shared between an HS-CAN frame and an MS-CAN frame (gateway candidates) ===")
for ms in sorted(ms_fo):
    for hs in sorted(hs_fo):
        shared=fo_sigs[ms]&fo_sigs[hs]
        if shared:
            print(f"\nMS fo=0x{ms:08X}  <-  HS fo=0x{hs:08X} : {len(shared)} shared sigs")
            for s in sorted(shared):
                print(f"    sig=0x{s:08X}  HS@{[hex(x) for x in fo_sig_loc[hs][s]]}  MS@{[hex(x) for x in fo_sig_loc[ms][s]]}")
