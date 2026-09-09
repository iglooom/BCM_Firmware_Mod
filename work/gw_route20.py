import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def isram(v): return 0x40000000<=v<0x40018000
def issig(v): return 0x40000600<=v<0x40000E00

netrng={"HS-CAN":(0x400001A0,0x40000200),"net1":(0x4000022C,0x40000284),
        "net2":(0x400002E0,0x40000338),"net3":(0x40000394,0x400003EC),
        "net4":(0x40000448,0x400004A0),"MS-CAN":(0x400004FC,0x40000554),
        "MSX-CAN":(0x40000588,0x400005E0)}
def netof(v):
    for n,(lo,hi) in netrng.items():
        if lo<=v<hi: return n
    return None

# Parse full 20-byte records across F10A: [sigA][sigB][frameObj][pk1][pk2]
recs=[]
a=0x140000
while a<0x15BF00-20:
    sA=u32(a); sB=u32(a+4); fo=u32(a+8); pk1=u32(a+12); pk2=u32(a+16)
    n=netof(fo)
    if n and issig(sA) and issig(sB):
        recs.append((a,n,fo,sA,sB,pk1,pk2)); a+=20; continue
    a+=4
print("total 20-byte [sigA][sigB][frameObj][pk1][pk2] records:",len(recs))

# Known MSX single-bit signals: sigRAM -> (byte,bitmask)
known={0x40000B58:(0,0x01),0x40000B38:(1,0x02),0x40000B41:(2,0x04),0x40000B7B:(3,0x08),
       0x40000B84:(4,0x10),0x40000B46:(5,0x08),0x40000B4F:(6,0x04),0x40000B69:(7,0x20),
       0x40000B72:(8,0x40),0x40000B60:(9,0x10)}
print("\n=== calibration: records whose sigA/sigB is a known MSX bit ===")
for a,n,fo,sA,sB,pk1,pk2 in recs:
    for s in (sA,sB):
        if s in known:
            b,m=known[s]
            print(f"  @{a:06X} {n} fo=0x{fo:08X} sigA=0x{sA:08X} sigB=0x{sB:08X} pk1={pk1:08X} pk2={pk2:08X}  [known {s:08X}=byte{b} mask{m:02X}]")
            break
