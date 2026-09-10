import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]
def u8(a): return img[a]
idx=34
print("HS 0x100 MB index 34 copier records:")
found=[]
for a in range(0x10000,min(0x160000,len(img))-28):
    if u8(a+0x19)==idx:
        dest=u32(a); dlc=u8(a+0x18); mask=u8(a+0x1a); sf=u32(a+8)
        if 0x40007A00<=dest<0x40007D00 and 1<=dlc<=8 and mask!=0:
            found.append((a,dest,dlc,mask,sf))
            print("  @0x%06X dest=0x%08X DLC=%d mask=0x%02X(%08b) sf=0x%08X"%(a,dest,dlc,mask,mask,sf))
for a,dest,dlc,mask,sf in found:
    below=bin(mask & 0x7F).count("1")
    copied=(mask>>7)&1
    if copied:
        print("  rec@0x%06X: d7 lands @0x%08X"%(a,dest+below))
    else:
        print("  rec@0x%06X: d7 NOT copied (mask bit7=0)"%a)
