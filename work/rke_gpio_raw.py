import struct
from collections import Counter, defaultdict
IMG="/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin"
d=open(IMG,"rb").read()
print("image bytes:",len(d))

# 1) Which peripheral high-halfwords appear as e_lis immediates?
# e_lis rD,imm  (VLE) encodings vary; instead do a raw scan for BE 32-bit words that look like periph addrs
# and for 16-bit immediates 0xC3F9 / 0xFFF4 / 0xFFF9 embedded in the stream.
def count_hi(hi):
    pat=struct.pack(">H",hi)
    # count occurrences on even and odd; report both
    n=d.count(pat)
    return n
for hi in (0xC3F9,0xFFF4,0xFFF9,0xFFFC,0xFFF8,0xC3FA,0xC3FE):
    print("hi 0x%04X appears %d times as BE halfword"%(hi,count_hi(hi)))

# 2) Full 32-bit BE constant scan for the exact pad-register addresses (both SIU base theories)
SIU_CANDS=[0xC3F90000, 0xFFF48000, 0xFFF90000]
def pad(port,pin):
    base={'A':0,'B':16,'C':32,'D':48,'E':64,'F':80,'G':96,'H':112,'I':128}[port]
    return base+pin
targets={}
for siu in SIU_CANDS:
    for name,(p,n) in (("LOCK_PI15",('I',15)),("UNLOCK_PF12",('F',12))):
        pd=pad(p,n)
        targets[(siu,name,"GPDI")]=siu+0x800+pd
        targets[(siu,name,"GPDO")]=siu+0x600+pd
        targets[(siu,name,"PCR")] =siu+0x40+2*pd
    # parallel port in/out regs (per 16-pin port, 16-bit)
    for name,port in (("LOCK_portI",'I'),("UNLOCK_portF",'F')):
        pidx={'A':0,'B':1,'C':2,'D':3,'E':4,'F':5,'G':6,'H':7,'I':8}[port]
        targets[(siu,name,"PGPDI")]=siu+0xC00+2*pidx
        targets[(siu,name,"PGPDO")]=siu+0x600+2*pidx  # parallel out base actually 0x600? (byte GPDO overlaps) - approx

print("\n=== exact 32-bit BE constant matches in image ===")
found=False
for k,addr in sorted(targets.items(), key=lambda kv:kv[1]):
    pat=struct.pack(">I",addr)
    offs=[]
    start=0
    while True:
        i=d.find(pat,start)
        if i<0: break
        offs.append(i); start=i+1
    if offs:
        found=True
        print("  %s reg 0x%08X : %d matches at file offs %s"%(k, addr, len(offs), [hex(o) for o in offs[:8]]))
if not found: print("  (no exact 32-bit constant matches for any candidate)")

# 3) Also scan for the SIU base itself as a 32-bit constant (bring-up tables often hold the base)
print("\n=== SIU base constants present? ===")
for siu in SIU_CANDS+[0xC3F90040,0xC3F90600,0xC3F90800,0xC3F90C00]:
    pat=struct.pack(">I",siu); print("  0x%08X : %d"%(siu, d.count(pat)))
