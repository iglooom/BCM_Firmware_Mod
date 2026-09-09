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
def flat(path):
    d=open(path,'rb').read(); he=hdr_end(d); off=he
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    p=off; bl={}
    while p+8<=len(d):
        s,l=struct.unpack('>II',d[p:p+8])
        if l==0 or p+8+l+2>len(d): break
        bl[s]=d[p+8:p+8+l]; p=p+8+l+2
    lo=0x10000; hi=0x140000; buf=bytearray(b'\xFF'*(hi-lo))
    for s,data in bl.items():
        if lo<=s<hi: buf[s-lo:s-lo+len(data)]=data
    return buf,lo
A,LO=flat(ROOT+"/JV6T-14C094-AB.VBF")
B,_=flat(ROOT+"/JV6T-14C094-AD.VBF")
STORE=0x13FFFC
targA=0x6288; targB=0x7572
def seg(buf,a,b): return bytes(buf[a-LO:b-LO])

def crc16_ccitt(data,init=0xFFFF):
    c=init
    for by in data:
        c^=by<<8
        for _ in range(8):
            c=((c<<1)^0x1021)&0xFFFF if (c&0x8000) else (c<<1)&0xFFFF
    return c
def crc16_ccitt_rev(data,init=0xFFFF):
    # reflected 0x8408
    c=init
    for by in data:
        c^=by
        for _ in range(8):
            c=(c>>1)^0x8408 if (c&1) else c>>1
    return c
def sum16(data):
    s=0
    for k in range(0,len(data)-1,2): s=(s+struct.unpack_from(">H",data,k)[0])&0xFFFF
    return s
def sum16le(data):
    s=0
    for k in range(0,len(data)-1,2): s=(s+struct.unpack_from("<H",data,k)[0])&0xFFFF
    return s
def sum8(data): return sum(data)&0xFFFF
def xor16(data):
    x=0
    for k in range(0,len(data)-1,2): x^=struct.unpack_from(">H",data,k)[0]
    return x

algos={"crc16ccitt":crc16_ccitt,"crc16ccitt_rev":crc16_ccitt_rev,
       "sum16be":sum16,"sum16le":sum16le,"sum8":sum8,"xor16":xor16}

# candidate ranges: start at code start (0x10020 / 0x10000 / 0x11800) end before the stored word / part-number
starts=[0x10000,0x10020,0x11800,0x10100]
ends=[STORE, 0x13FFE0, 0x13FF00, 0x140000, 0x13FFFE, 0x13FFFC]
print("target AB=0x%04X AD=0x%04X @0x%06X"%(targA,targB,STORE))
found=False
for st in starts:
    for en in ends:
        if en<=st: continue
        dA=seg(A,st,en); dB=seg(B,st,en)
        for nm,fn in algos.items():
            try:
                cA=fn(dA); cB=fn(dB)
            except Exception: continue
            if cA==targA and cB==targB:
                print("  *** MATCH algo=%s range[0x%06X..0x%06X)"%(nm,st,en)); found=True
            # also try with complement / init 0
if not found:
    print("  no exact match on standard algos/ranges; showing computed values for crc16ccitt over a few ranges:")
    for st in starts:
        for en in [STORE,0x13FFE0,0x140000]:
            dA=seg(A,st,en);dB=seg(B,st,en)
            print("   crc16ccitt[0x%06X..0x%06X) AB=%04X AD=%04X | sum16be AB=%04X AD=%04X"%(
                st,en,crc16_ccitt(dA),crc16_ccitt(dB),sum16(dA),sum16(dB)))
