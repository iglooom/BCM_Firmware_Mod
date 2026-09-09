import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def isram(v): return 0x40000000<=v<0x40018000

# The 28-byte frame descriptor records: last word = id<<18. Scan whole F10A for records
# with w6 = id<<18 (low18=0) AND w0 = RAM ptr (frame image/ctrl) AND w3 = RAM ptr.
print("=== all 28-byte frame descriptors (w0 RAM, w3 RAM, w6=id<<18) ===")
recs=[]
a=0x1B000
while a < 0x1D000:
    w=[u32(a+4*i) for i in range(7)]
    if isram(w[0]) and isram(w[3]) and w[6]!=0 and (w[6]&0x3FFFF)==0 and (w[6]>>18)<0x800:
        recs.append((a,w))
        a+=28
    else:
        a+=4
print("count:",len(recs))
for a,w in recs:
    cid=w[6]>>18
    tag=" <<<" if cid in (0x0C0,0x060,0x020) else ""
    print(f"{a:06X} id=0x{cid:03X} ctrl/stat={w[0]:08X} img={w[3]:08X} f10a={w[4]:08X} dlcw={w[5]:08X}{tag}")
