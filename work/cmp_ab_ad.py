#!/usr/bin/env python3
import struct, hashlib
ROOT="/home/gl/Projects/ford/BCM/Research"
def hdr_end(d):
    i=d.find(b'header'); depth=0; j=d.find(b'{',i)
    while j<len(d):
        if d[j]==0x7b: depth+=1
        elif d[j]==0x7d:
            depth-=1
            if depth==0: return j+1
        j+=1
def parse(path):
    d=open(path,'rb').read(); he=hdr_end(d); off=he
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    ds=off; blocks=[]; p=off
    while p+8<=len(d):
        s,l=struct.unpack('>II',d[p:p+8])
        if l==0 or p+8+l+2>len(d): break
        blocks.append((s,l,d[p+8:p+8+l],struct.unpack('>H',d[p+8+l:p+8+l+2])[0]))
        p=p+8+l+2
    return d,ds,blocks,d[:he].decode('latin1')

for f in ("JV6T-14C094-AB.VBF","JV6T-14C094-AD.VBF"):
    d,ds,blocks,hdr=parse(ROOT+"/"+f)
    print("=== %s  sha256=%s"%(f,hashlib.sha256(d).hexdigest()[:16]))
    print("   header:")
    for line in hdr.splitlines():
        ls=line.strip()
        if ls and not ls.startswith("//"): print("     "+ls)
    for s,l,bd,crc in blocks:
        print("   block load=0x%08X len=0x%X crc16=0x%04X"%(s,l,crc))
