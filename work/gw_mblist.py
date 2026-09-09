import struct
img=open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

ctrls=[("CAN0 HS-CAN 500k",0x1464E0,0x146530),
       ("CAN1 MS-CAN 125k",0x146900,0x146950),
       ("CAN2 MSX-CAN 125k",0x146C50,0x146CA0)]
for name,cbase,mbstart in ctrls:
    print(f"\n===== {name}  ctrl@{cbase:06X}  MBlist@{mbstart:06X} =====")
    a=mbstart; idx=0
    while a < mbstart+0x400:
        idv=u32(a); flags=u32(a+4); mask=u32(a+8)
        # stop when leaving plausible records
        if flags not in (0x08080000,0x04080000,0x08040000,0x00080000,0x04040000) and idv==0xFFFFFFFF:
            break
        if idv==0 and flags==0 and mask==0: break
        canid=idv>>18
        tag=""
        if canid in (0x0C0,0x060,0x020): tag="  <<<< TARGET"
        print(f"  MB[{idx:2d}] @{a:06X}  id<<18={idv:08X} id=0x{canid:03X}  flags={flags:08X} mask={mask:08X}{tag}")
        a+=12; idx+=1
        if idx>60: break
