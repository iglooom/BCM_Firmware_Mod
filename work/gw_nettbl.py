import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

# Master network table: base record 0x178B0, stride 0x5C, +4=ctrl desc ptr
print("=== master network records (base 0x178B0 stride 0x5C) ===")
base=0x178B0; stride=0x5C
for i in range(9):
    r=base+i*stride
    w=[u32(r+4*k) for k in range(0x17)]
    ctrl=w[1]
    canname={0x1464E0:"CAN0/HS-500k",0x146900:"CAN1/MS-125k",0x146C50:"CAN2/MSX-125k"}.get(ctrl,"")
    print(f"\nnet{i} @0x{r:05X} ctrlDesc=0x{ctrl:06X} {canname}")
    print("   words:", " ".join("%08X"%x for x in w))
