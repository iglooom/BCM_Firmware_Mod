#!/usr/bin/env python3
import struct, zlib
ROOT="/home/gl/Projects/ford/BCM/Research"
def hdr_end(d):
    i=d.find(b'header'); depth=0; j=d.find(b'{',i)
    while j<len(d):
        if d[j]==0x7b: depth+=1
        elif d[j]==0x7d:
            depth-=1
            if depth==0: return j+1
        j+=1
def blocks(path):
    d=open(path,'rb').read(); he=hdr_end(d); off=he
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    p=off; out={}
    while p+8<=len(d):
        s,l=struct.unpack('>II',d[p:p+8])
        if l==0 or p+8+l+2>len(d): break
        out[s]=d[p+8:p+8+l]; p=p+8+l+2
    return out
def flat(path):
    bl=blocks(path)
    lo=0x10000; hi=0x140000
    buf=bytearray(b'\xFF'*(hi-lo))
    for s,data in bl.items():
        if s< lo or s>=hi: continue
        buf[s-lo:s-lo+len(data)]=data
    return buf,lo
A,LO=flat(ROOT+"/JV6T-14C094-AB.VBF")
B,_ =flat(ROOT+"/JV6T-14C094-AD.VBF")
N=len(A)

# index differing aligned words: (valA,valB) -> list of addr  (BE and LE)
from collections import defaultdict
idxBE=defaultdict(list); idxLE=defaultdict(list)
i=0
while i+4<=N:
    a=struct.unpack_from(">I",A,i)[0]; b=struct.unpack_from(">I",B,i)[0]
    if a!=b:
        idxBE[(a,b)].append(LO+i)
    aL=struct.unpack_from("<I",A,i)[0]; bL=struct.unpack_from("<I",B,i)[0]
    if aL!=bL:
        idxLE[(aL,bL)].append(LO+i)
    i+=4
# also 16-bit
idx16BE=defaultdict(list)
i=0
while i+2<=N:
    a=struct.unpack_from(">H",A,i)[0]; b=struct.unpack_from(">H",B,i)[0]
    if a!=b: idx16BE[(a,b)].append(LO+i)
    i+=2
print("distinct differing 32BE pairs:",len(idxBE),"  16BE:",len(idx16BE))

bounds=[0x10000,0x10020,0x18000,0x20000,0x40000,0x60000,0x80000,0xA0000,0xC0000,0xE0000,0x100000,0x120000,0x140000]
def seg(buf,a,b): return bytes(buf[a-LO:b-LO])
def algos(data):
    yield "sum32", (sum(data)&0xFFFFFFFF)
    yield "crc32", zlib.crc32(data)&0xFFFFFFFF
    # sum of 16-bit BE words
    s=0
    for k in range(0,len(data)-1,2): s+=struct.unpack_from(">H",data,k)[0]
    yield "sum16w", s&0xFFFFFFFF
    # xor32
    x=0
    for k in range(0,len(data)-3,4): x^=struct.unpack_from(">I",data,k)[0]
    yield "xor32", x&0xFFFFFFFF

print("\n=== hunting (algo,range) whose (cAB,cAD) is stored at same offset in both ===")
hits=[]
for bi in range(len(bounds)):
    for bj in range(bi+1,len(bounds)):
        a,b=bounds[bi],bounds[bj]
        dA=seg(A,a,b); dB=seg(B,a,b)
        for name,cA in algos(dA):
            # compute same algo for B
            cB=dict(algos(dB))[name]
            if cA==cB: continue
            for idx,lbl in ((idxBE,"32BE"),(idxLE,"32LE")):
                locs=idx.get((cA,cB))
                if locs:
                    for L in locs:
                        hits.append((name,a,b,lbl,L,cA,cB))
# also 16-bit low half of sum
for h in hits:
    name,a,b,lbl,L,cA,cB=h
    print("  HIT algo=%s range[0x%06X..0x%06X) store@0x%06X %s  AB=0x%08X AD=0x%08X"%(name,a,b,L,lbl,cA,cB))
if not hits: print("  (no direct hit with simple algos/whole-erase-ranges)")
