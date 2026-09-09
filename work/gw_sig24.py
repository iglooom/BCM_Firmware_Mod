import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def isram(v): return 0x40000000<=v<0x40018000
def issig(v): return 0x40000600<=v<0x40000E00   # signal RAM range
netrng={"HS-CAN":(0x400001A0,0x40000200),"net1":(0x4000022C,0x40000284),
        "net2":(0x400002E0,0x40000338),"net3":(0x40000394,0x400003EC),
        "net4":(0x40000448,0x400004A0),"MS-CAN":(0x400004FC,0x40000554),
        "MSX-CAN":(0x40000588,0x400005E0)}
def netof(v):
    for n,(lo,hi) in netrng.items():
        if lo<=v<hi: return n
    return None

# 24-byte signal descriptors: w0=byte<<8|bitmask (small), w4=sigRAM, w5=frameObj
recs=[]
a=0x140000
while a<0x15BF00-24:
    w=[u32(a+4*i) for i in range(6)]
    n=netof(w[5])
    if n and issig(w[4]):
        byte=(w[0]>>8)&0xFF; bm=w[0]&0xFF
        # sanity: bitmask should be a valid contiguous mask or plausible; byte<8
        if byte<8 and (w[0]>>16)==0:
            recs.append((a,n,w[5],byte,bm,w[4],w[1],w[2],w[3])); a+=24; continue
    a+=4
print("total 24-byte signal descriptors:",len(recs))
from collections import Counter,defaultdict
byfobj=defaultdict(list)
for r in recs: byfobj[(r[1],r[2])].append(r)
print("frameObjs:",len(byfobj))
with open("sig24.txt","w") as f:
    for (n,fo),rs in sorted(byfobj.items()):
        f.write(f"\n### {n} frameObj=0x{fo:08X} ({len(rs)} signals)\n")
        for a,nn,ff,byte,bm,sig,w1,w2,w3 in rs:
            f.write(f"  @{a:06X} byte{byte} mask{bm:02X} sig=0x{sig:08X} dlc={w1:08X} m1={w2:08X} m2={w3:08X}\n")
print("saved sig24.txt")
# print per-net frameObj list
for n in netrng:
    fos=sorted(set(fo for (nn,fo) in byfobj if nn==n))
    if fos: print(f"{n}: frameObjs "+" ".join("0x%08X"%x for x in fos))
