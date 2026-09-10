import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
# For each net ctrlDesc, header = u32(ctrlDesc+0x44); TX table base = u32(header+4); count via RX header+0x11.
# Actually RX copier: base=u32(u32(ctrlDesc+0x44)+8), count=u8(u32(ctrlDesc+0x44)+0x11)
# TX walker: base=u32(u32(ctrlDesc+0x44)+4), stride 0x20; rec+8=image, rec+0x1a=MBidx, rec+0xc=srcsig, rec+0x1b=mask
for nm,cd in [("HS",0x1464E0),("MS",0x146900),("MSX",0x146C50)]:
    # locate ctrlDesc precisely: FlexCAN base at +0x10
    # verify
    hdrp=u32(cd+0x44)
    print(f"\n{nm} ctrlDesc@0x{cd:06X} base(+0x10)=0x{u32(cd+0x10):08X} hdr(+0x44)=0x{hdrp:08X}")
    if not (0x10000<=hdrp<0x160000): 
        print("   (hdr not a flash ptr; skipping)"); continue
    txbase=u32(hdrp+4); rxbase=u32(hdrp+8); cnt=u8(hdrp+0x11)
    print(f"   TXtable=0x{txbase:08X} RXtable=0x{rxbase:08X} count={cnt}")
    if 0x10000<=txbase<0x160000:
        print("   TX descriptors (32B): MBidx -> image, srcsig, mask")
        for i in range(cnt+40):
            r=txbase+i*0x20
            if r+0x20>N: break
            mb=u8(r+0x1a); image=u32(r+8); src=u32(r+0xc); mask=u8(r+0x1b)
            if u32(r+8)==0 and u32(r+0xc)==0: break
            if mb<=17:
                print(f"     MB{mb:2d} @0x{r:06X} image=0x{image:08X} src=0x{src:08X} mask=0x{mask:02X}")
