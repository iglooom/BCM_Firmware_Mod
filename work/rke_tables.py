import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# Find contiguous 28-byte record tables: a run where +0x00 is a frame-image RAM ptr (0x40000600..0x40000E00)
# and stride 28 holds for >=8 records. Report each table with its MB-index column (+0x19).
def is_img(v): return 0x40000600<=v<0x40000E00
tables=[]
a=0x150000
while a < min(0x15C000,N)-28:
    # try to detect a table start
    if is_img(u32(a)) and is_img(u32(a+28)) and is_img(u32(a+56)):
        # walk
        recs=[]
        b=a
        while b<N-28 and is_img(u32(b)):
            recs.append(b); b+=28
        if len(recs)>=6:
            tables.append((a,recs)); a=b; continue
    a+=4
for start,recs in tables:
    mbs=[u8(r+0x19) for r in recs]
    print(f"\nTABLE @0x{start:06X}: {len(recs)} recs, MBidx(+0x19) range {min(mbs)}..{max(mbs)}")
    for r in recs:
        dest=u32(r); mb19=u8(r+0x19); mb1a=u8(r+0x1a); dlc=u8(r+0x18); mask=u8(r+0x1a)
        print(f"   @0x{r:06X} img=0x{dest:08X} +0x18={dlc:#04x} +0x19(MB?)={mb19} +0x1a={mb1a:#04x}")
