#!/usr/bin/env python3
"""Build COMBINED acc-fix + RKE-lock APP/EXE VBF for the BCM.
  acc-fix: RES+/LIM remap on TX HS-CAN 0x030 (CAN0 MB0). [unchanged from shipped acc-fix]
  rke-lock: force CLockCmd=LOCK on TX MS-CAN 0x3A (CAN1 MB1) when
            0x100 d7.0 (RKE LOCK) & d6.2 (UB) & d1.7 (key-outside) & 0x3A0 d0 hi-nibble==Run(4).
Both live in the two shared caves (0x117100 single packer, 0x117300 walker); hooks 0xFC2C2/0xFC440.
Repairs internal sum8@0x13FFFE + per-block CRC16 + file CRC32. APP VBF only.
Run build_caves.py first (writes patch_blobs.json next to this script)."""
import struct, zlib, hashlib, os, shutil, json, re
HERE=os.path.dirname(os.path.abspath(__file__))
ROOT="/home/gl/Projects/ford/BCM/Research"
OUT=HERE
BK =os.path.join(ROOT,"work","backups")
bl=json.load(open(os.path.join(HERE,"patch_blobs.json")))
c1=bytes(bl["c1"]); h1=bytes(bl["h1"]); c2=bytes(bl["c2"]); h2=bytes(bl["h2"])
CAVE1=bl["cave1"]; CAVE2=bl["cave2"]
# expected original bytes: hooks displace the SAME OEM instrs acc-fix documented; caves are 0xFF pad
EDITS=[(0x000FC2C2,h1,b"\x5C\xEA\x00\x00"),(0x000FC440,h2,b"\x00\xE7\xB0\x7D"),
       (CAVE1,c1,b"\xFF"*len(c1)),(CAVE2,c2,b"\xFF"*len(c2))]
def crc16(d):
    c=0xFFFF
    for b in d:
        c^=b<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xFFFF if (c&0x8000) else (c<<1)&0xFFFF
    return c
def hdr_end(d):
    i=d.find(b'header'); depth=0; j=d.find(b'{',i)
    while j<len(d):
        if d[j]==0x7b: depth+=1
        elif d[j]==0x7d:
            depth-=1
            if depth==0: return j+1
        j+=1
def parse(path):
    d=bytearray(open(path,'rb').read()); he=hdr_end(d); off=he
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    ds=off; blocks=[]; p=off
    while p+8<=len(d):
        s,l=struct.unpack('>II',d[p:p+8])
        if l==0 or p+8+l+2>len(d): break
        blocks.append(dict(start=s,dataoff=p+8,length=l,crcoff=p+8+l)); p=p+8+l+2
    return d,ds,blocks
app=os.path.join(ROOT,"JV6T-14C094-AD.VBF")
h_app=hashlib.sha256(open(app,'rb').read()).hexdigest(); assert h_app.startswith("1569cde589ec546f")
bpath=os.path.join(BK,os.path.basename(app)+f".orig_{h_app[:12]}")
if not os.path.exists(bpath): shutil.copy2(app,bpath)
d,ds,blocks=parse(app)
appblk=[b for b in blocks if b['start']==0x10020][0]; rchw=[b for b in blocks if b['start']==0x10000][0]
def fo(fa): assert 0x10020<=fa<0x10020+appblk['length']; return appblk['dataoff']+(fa-0x10020)
assert CAVE1+len(c1)<=CAVE2, "cave overlap"
for fa,newb,expect in EDITS:
    o=fo(fa); got=bytes(d[o:o+len(expect)])
    assert got==expect,"at 0x%X exp %s got %s"%(fa,expect.hex(),got.hex())
    d[o:o+len(newb)]=newb; print("  patched 0x%06X (%dB)"%(fa,len(newb)))
# layer3 internal sum8 over RCHW(0x10000)+app(0x10020) region up to 0x13FFFE
flat=bytearray(b'\xFF'*(0x140000-0x10000))
flat[0:rchw['length']]=d[rchw['dataoff']:rchw['dataoff']+rchw['length']]
flat[0x20:0x20+appblk['length']]=d[appblk['dataoff']:appblk['dataoff']+appblk['length']]
o=fo(0x13FFFE); old=struct.unpack_from(">H",d,o)[0]; new=sum(flat[0:0x13FFFE-0x10000])&0xFFFF
struct.pack_into(">H",d,o,new); print("  sum8 0x%04X->0x%04X"%(old,new))
for b in blocks: d[b['crcoff']:b['crcoff']+2]=struct.pack('>H',crc16(bytes(d[b['dataoff']:b['dataoff']+b['length']])))
m=re.search(rb'file_checksum\s*=\s*0x([0-9A-Fa-f]+)',bytes(d[:ds])); fc=zlib.crc32(bytes(d[ds:]))&0xFFFFFFFF
w=len(m.group(1)); d[m.start(1):m.end(1)]=("%0*X"%(w,fc)).encode()
outp=os.path.join(OUT,"JV6T-14C094-AD_accfix-rkelock.VBF"); open(outp,'wb').write(d)
print("  file_crc32 -> 0x%08X"%fc); print("WROTE",outp,"sha256",hashlib.sha256(bytes(d)).hexdigest())
