import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

# Reception descriptor table for HS @0x18000 (ctrlDesc+0x44). 32-byte records observed:
# +0x00 0  +0x04 0  +0x08 MBbit  +0x0C ptr->0x14xxxx (routing/handler)  +0x10 0x146FA0  +0x14 0x146FA4  +0x18 image RAM  +0x1C 0
# Dump many and collect (mbbit, handlerptr, image)
def dump_rxdesc(name, base, n):
    print(f"\n===== {name} reception descriptors @0x{base:06X} =====")
    out=[]
    for i in range(n):
        a=base+i*32
        f2=u32(a+8); hp=u32(a+0x0C); img_=u32(a+0x18)
        if f2==0 and hp==0 and img_==0: 
            # maybe end
            if i>4: break
            continue
        print(f"  #{i:2d} @0x{a:06X} mbbit=0x{f2:08X} handler->0x{hp:06X} image=0x{img_:08X}")
        out.append((a,f2,hp,img_))
    return out

hs=dump_rxdesc("HS",0x18000,70)
