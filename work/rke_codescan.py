import struct
img=open("flash_merged.bin","rb").read()
N=len(img)
def u16(a): return struct.unpack_from(">H",img,a)[0]
CODE=range(0x10000,0x140000)
# VLE e_lis / e_or2i / e_add16i build 32-bit constants in halves.
# Look anywhere in code for the low half 0x0918 (or 0x0900/0x0910/0x0908) AND a 0x4000 half within a small window.
lows={0x0918:"exact base d0",0x0910:"page910",0x0900:"page900",0x0908:"page908",0x091E:"d6",0x091F:"d7"}
for low,lbl in lows.items():
    for a in CODE:
        if a+1>=N: break
        if u16(a)==low:
            # window +/- 12 bytes for a 0x4000 half
            win=[d for d in range(-12,14,2) if 0<=a+d<N-1 and u16(a+d)==0x4000]
            if win:
                ctx=" ".join("%04X"%u16(a+d) for d in range(-8,10,2))
                print("low 0x%04X [%s] @0x%06X  hi-half offsets %s | ctx: %s"%(low,lbl,a,win,ctx))
