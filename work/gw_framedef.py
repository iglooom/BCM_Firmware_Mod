import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

netrng={"HS-CAN":(0x400001A0,0x40000200),"MS-CAN":(0x400004FC,0x40000554),
        "MSX-CAN":(0x40000588,0x400005E0)}
def netof(v):
    for n,(lo,hi) in netrng.items():
        if lo<=v<hi: return n
    return None

# For target ids, find any 32-bit word == id<<18 that has a frameObj of the matching net
# within +/- 4 words. Report the full 8-word window.
targets={0x03000000:("0x0C0","HS-CAN"),0x01800000:("0x060","HS-CAN"),0x00800000:("0x020","MS-CAN")}
print("=== id<<18 windows with matching-net frameObj nearby ===")
a=0x140000
while a<0x15BF00-4:
    v=u32(a)
    if v in targets:
        idn,net=targets[v]
        win=[u32(a-16+4*i) for i in range(10)]
        fo=None
        for j,w in enumerate(win):
            if netof(w)==net:
                fo=(j-4,w)
        if fo:
            print(f"@0x{a:06X} {idn} (want {net}) frameObj=0x{fo[1]:08X}@off{fo[0]*4}")
            print("   win[-16..+20]:", " ".join("%08X"%x for x in win))
    a+=4
