import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

# Decode FlexCAN CTRL reg values to infer baud (higher PRESDIV -> slower)
# CTRL word candidates: offset +0x30 in each controller record
for name,ctrlword_addr in [("CAN0@FFFC0000",0x146510),("CAN1@FFFC4000",0x146930),("CAN2@FFFC8000",0x146C80)]:
    c=u32(ctrlword_addr)
    presdiv=(c>>24)&0xFF
    rjw=(c>>22)&0x3
    pseg1=(c>>19)&0x7
    pseg2=(c>>16)&0x7
    propseg=c&0x7
    # time quanta = 1+(propseg+1)+(pseg1+1)+(pseg2+1)
    tq=1+(propseg+1)+(pseg1+1)+(pseg2+1)
    # assume periph clock 64MHz typical; baud = fclk/((presdiv+1)*tq)
    for fclk in (64e6,):
        baud=fclk/((presdiv+1)*tq)
        print(f"{name}: CTRL=0x{c:08X} PRESDIV={presdiv} PSEG1={pseg1} PSEG2={pseg2} PROPSEG={propseg} TQ={tq} -> ~{baud/1000:.1f}kbps @ {fclk/1e6:.0f}MHz")
