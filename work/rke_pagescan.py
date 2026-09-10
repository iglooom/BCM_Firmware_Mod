import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u16(a): return struct.unpack_from(">H",img,a)[0]
CODE_LO,CODE_HI=0x10000,0x140000

# VLE 32-bit forms of interest (big-endian, 4-byte, first 6 bits = opcode group):
#  e_lis rD,UIMM  : encoded like e_add2is? Actually VLE 'e_lis' = e_or2is variant.
#   Practical approach: find any 16-bit halfword == 0x4000 in code (candidate high half of 0x40000xxx),
#   then look for a nearby halfword equal to a 0x09xx low value (0x0900..0x091F) OR a small displacement
#   load. Report clusters.
hits=[]
for a in range(CODE_LO,CODE_HI):
    if a+1>=N: break
    if u16(a)==0x4000:
        # window for a 0x09xx low-half or a byte offset 0x1E/0x1F / 6 / 7
        lows=[(d,u16(a+d)) for d in range(2,20,2) if a+d+1<N and 0x0900<=u16(a+d)<=0x0920]
        if lows:
            hits.append((a,lows))
print(f"0x4000 high-half followed by 0x09xx low-half within 18 bytes: {len(hits)}")
for a,lows in hits[:40]:
    ctx=" ".join("%04X"%u16(a+d) for d in range(0,16,2))
    print(f"  @0x{a:06X}: {[(d,hex(v)) for d,v in lows]}  ctx: {ctx}")
