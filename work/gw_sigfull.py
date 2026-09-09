import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u16(a): return struct.unpack_from(">H",img,a)[0]
def isram(v): return 0x40000000<=v<0x40018000

# Full 28-byte sig-descriptor scan across F10A:
# pattern [sigRAM][sigRAM2][sigRAM3(frame databyte)][frameRef RAM][handler 0x00144xxx][spec u32][mask u32]
print("=== 28-byte sig descriptors (w4 handler in 0x144000..0x146000) ===")
recs=[]
a=0x150000
while a < 0x15AE00:
    w=[u32(a+4*i) for i in range(7)]
    if isram(w[2]) and isram(w[3]) and 0x144000<=w[4]<0x146000:
        recs.append((a,w)); a+=28
    else:
        a+=4
print("count:",len(recs))
from collections import Counter
frefs=Counter(w[3] for a,w in recs)
print("distinct frameRefs:",len(frefs))
print("frameRef counts:", {hex(k):v for k,v in sorted(frefs.items())})
with open("sig_desc_full.txt","w") as f:
    for a,w in recs:
        f.write("%06X "%a + " ".join("%08X"%x for x in w)+"\n")
print("saved sig_desc_full.txt; sample:")
for a,w in recs[:8]:
    print("  %06X "%a + " ".join("%08X"%x for x in w))
