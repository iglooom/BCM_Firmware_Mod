import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def issig(v): return 0x40000600<=v<0x40000E00
netrng={"HS":(0x400001A0,0x40000200),"MS":(0x400004FC,0x40000554),"MSX":(0x40000588,0x400005E0),
        "n1":(0x4000022C,0x40000284),"n2":(0x400002E0,0x40000338),"n3":(0x40000394,0x400003EC),
        "n4":(0x40000448,0x400004A0)}
def netof(v):
    for n,(lo,hi) in netrng.items():
        if lo<=v<hi: return n
    return None

# Parse ALL aligned 20-byte records: [frameObj][spec1][spec2][sigA][sigB]
recs=[]
a=0x140000
while a<0x15BF00-20:
    fo=u32(a);s1=u32(a+4);s2=u32(a+8);sA=u32(a+12);sB=u32(a+16)
    if netof(fo) and issig(sA) and issig(sB):
        recs.append((a,fo,s1,s2,sA,sB)); a+=20; continue
    a+=4

def dump_frame(net, cid, label):
    print(f"\n===== {label}: net={net} CAN id=0x{cid:03X} (spec1>>18==0x{cid:03X}) =====")
    out=[]
    for a,fo,s1,s2,sA,sB in recs:
        if netof(fo)==net and (s1>>18)==cid:
            out.append((a,fo,s1,s2,sA,sB))
    print(f"  {len(out)} records")
    for a,fo,s1,s2,sA,sB in out:
        print(f"  @{a:06X} fo=0x{fo:08X} spec1={s1:08X} spec2={s2:08X} sigA=0x{sA:08X} sigB=0x{sB:08X}")
    return out

rx0c0=dump_frame("HS",0x0C0,"HS-CAN RX 0x0C0")
rx060=dump_frame("HS",0x060,"HS-CAN RX 0x060")
tx020=dump_frame("MS",0x020,"MS-CAN TX 0x020")
