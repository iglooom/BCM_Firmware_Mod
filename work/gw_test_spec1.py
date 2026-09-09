import struct
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

def parse_mb(start, stop):
    rx=set(); tx=set()
    a=start
    while a < stop:
        w0=u32(a); w1=u32(a+4)
        if (w0 & 0x3FFFF)==0 and 0 < (w0>>18) <= 0x7FF:
            idv=w0>>18; flag=(w1>>24)&0xFF
            if flag==0x04: rx.add(idv)
            elif flag==0x08: tx.add(idv)
            a+=12
        else: break
    return rx,tx
hs_rx,hs_tx=parse_mb(0x146530,0x146900)
ms_rx,ms_tx=parse_mb(0x146950,0x146C50)
hs_ids=hs_rx|hs_tx; ms_ids=ms_rx|ms_tx

# Load aligned records
recs=[]
for line in open("aligned_records.txt"):
    # 140034 fo=0x400001A1(HS) spec1=10048001 spec2=01010000 sigA=0x40000680 sigB=0x4000067F
    parts=line.split()
    off=int(parts[0],16)
    fo=int(parts[1].split('=')[1].split('(')[0],16)
    bus=parts[1].split('(')[1].rstrip(')')
    spec1=int(parts[2].split('=')[1],16)
    spec2=int(parts[3].split('=')[1],16)
    sigA=int(parts[4].split('=')[1],16)
    sigB=int(parts[5].split('=')[1],16)
    recs.append((off,fo,bus,spec1,spec2,sigA,sigB))

print("total aligned records:",len(recs))
# Hypothesis: id = (spec1>>18)&0x7FF is a valid ID on the record's bus
def busids(bus):
    return hs_ids if bus=="HS" else (ms_ids if bus=="MS" else set())
hit=0; miss=0; missex=[]
for off,fo,bus,spec1,spec2,sigA,sigB in recs:
    if bus not in ("HS","MS"): continue
    idv=(spec1>>18)&0x7FF
    if idv in busids(bus): hit+=1
    else:
        miss+=1
        if len(missex)<15: missex.append((off,bus,spec1,idv))
print(f"(spec1>>18)&0x7FF in bus id list:  HIT={hit}  MISS={miss}  ({100*hit/(hit+miss):.1f}% hit)")
print("miss examples (off,bus,spec1,decodedid):")
for m in missex: print("  0x%06X %s spec1=0x%08X id=0x%03X"%(m[0],m[1],m[2],m[3]))
