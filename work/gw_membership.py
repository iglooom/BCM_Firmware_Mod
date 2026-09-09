import struct, collections
img=open("flash_merged.bin","rb").read()
def u32(a): return struct.unpack_from(">I",img,a)[0]

# --- MB filter lists (authoritative IDs) ---
def parse_mb(start, stop):
    rows=[]
    a=start
    while a < stop:
        w0=u32(a); w1=u32(a+4); w2=u32(a+8)
        if (w0 & 0x3FFFF)==0 and 0 < (w0>>18) <= 0x7FF:
            rows.append((a, w0>>18, (w1>>24)&0xFF, w2)); a+=12
        else: break
    return rows
hs=parse_mb(0x146530,0x146900)
ms=parse_mb(0x146950,0x146C50)
hs_rx=[r[1] for r in hs if r[2]==0x04]; hs_tx=[r[1] for r in hs if r[2]==0x08]
ms_rx=[r[1] for r in ms if r[2]==0x04]; ms_tx=[r[1] for r in ms if r[2]==0x08]

# --- group routing records by frameObj ---
groups=collections.OrderedDict()
busof={}
for line in open("aligned_records.txt"):
    p=line.split()
    off=int(p[0],16)
    fo=int(p[1].split('=')[1].split('(')[0],16)
    bus=p[1].split('(')[1].rstrip(')')
    sigA=int(p[4].split('=')[1],16); sigB=int(p[5].split('=')[1],16)
    groups.setdefault(fo,[]); groups[fo].append((off,sigA,sigB))
    busof[fo]=bus

print("=== frameObj groups (signal-frame membership at frameObj level) ===")
print(f"{'frameObj':>10} {'bus':>4} {'#recs':>5} {'#uniqSig':>8}  sigRAM span")
for fo in sorted(groups):
    recs=groups[fo]
    sigs=set()
    for off,a,b in recs: sigs.add(a); sigs.add(b)
    sigs.discard(0x40000614)  # null
    span=f"0x{min(sigs):08X}..0x{max(sigs):08X}" if sigs else "-"
    print(f"0x{fo:08X} {busof[fo]:>4} {len(recs):5d} {len(sigs):8d}  {span}")

print("\ncounts: HS RX",len(hs_rx),"HS TX",len(hs_tx),"MS RX",len(ms_rx),"MS TX",len(ms_tx))
print("HS frameObjs:", sorted(f for f in groups if busof[f]=='HS'))
print("MS frameObjs:", sorted(f for f in groups if busof[f]=='MS'))
print("MSX frameObjs:", sorted(f for f in groups if busof[f]=='MSX'))
