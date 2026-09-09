import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u16(a): return struct.unpack_from(">H",img,a)[0]
def u8(a): return img[a]

# Controller descriptors at 0x1464E0, 0x146900, 0x146C50 (each 0x90-ish header then MB list)
for ctrl,base in [("CTRL@1464E0",0x1464E0),("CTRL@146900",0x146900),("CTRL@146C50",0x146C50)]:
    print(f"\n===== {ctrl} =====")
    for a in range(base, base+0x60, 16):
        vals=" ".join(f"{u32(a+i):08X}" for i in range(0,16,4))
        asc=''.join(chr(b) if 32<=b<127 else '.' for b in img[a:a+16])
        print(f"{a:06X}  {vals}  {asc}")
    # The base ptr word (0xFFFCx000) tells controller. find it
    for a in range(base,base+0x60,4):
        v=u32(a)
        if 0xFFFC0000<=v<0xFFFE0000:
            print(f"   -> FlexCAN base at 0x{a:06X} = 0x{v:08X}")
