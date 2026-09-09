import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def isram(v): return 0x40000000<=v<0x40018000

# Scan whole F10A for 28-byte frame descriptors: w0 RAM(status), w3 RAM(image), w6=id<<18
print("=== all 28-byte frame descriptors across F10A ===")
recs=[]
a=0x140000
while a < 0x15BF40-28:
    w=[u32(a+4*i) for i in range(7)]
    if isram(w[0]) and isram(w[3]) and w[6]!=0 and (w[6]&0x3FFFF)==0 and (w[6]>>18)<0x800:
        # extra: w0 and w3 in plausible ranges
        recs.append((a,w)); a+=28
    else:
        a+=4
print("count:",len(recs))
# group by contiguous blocks
prev=None
for a,w in recs:
    cid=w[6]>>18
    tag=" <<<TARGET" if cid in (0x0C0,0x060,0x020) else ""
    gap = "" if prev is None or a-prev==28 else "  --- new block ---"
    print(f"{a:06X}{gap} id=0x{cid:03X} stat={w[0]:08X} img={w[3]:08X} h={w[4]:08X} dlcw={w[5]:08X}{tag}")
    prev=a
