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
def seg(buf,a,b): return bytes(buf[a-LO:b-LO])
# erase sectors from header
sect=[(0x10000,0x8000),(0x18000,0x8000),(0x20000,0x20000),(0x40000,0x20000),
      (0x60000,0x20000),(0x80000,0x20000),(0xA0000,0x20000),(0xC0000,0x20000),
      (0xE0000,0x20000),(0x100000,0x20000),(0x120000,0x20000)]
print("=== per-erase-sector: does a checksum stay CONSTANT across AB vs AD despite diffs? ===")
for s,l in sect:
    da=seg(A,s,s+l); db=seg(B,s,s+l)
    if da==db:
        print("  0x%06X len0x%X: IDENTICAL"%(s,l)); continue
    su_a=sum(da)&0xFFFFFFFF; su_b=sum(db)&0xFFFFFFFF
    cr_a=zlib.crc32(da)&0xFFFFFFFF; cr_b=zlib.crc32(db)&0xFFFFFFFF
    # 32-bit word sum
    wa=sum(struct.unpack_from(">I",da,k)[0] for k in range(0,len(da)-3,4))&0xFFFFFFFF
    wb=sum(struct.unpack_from(">I",db,k)[0] for k in range(0,len(db)-3,4))&0xFFFFFFFF
    flags=[]
    if su_a==su_b: flags.append("SUM8-CONST=0x%08X"%su_a)
    if cr_a==cr_b: flags.append("CRC32-CONST=0x%08X"%cr_a)
    if wa==wb:     flags.append("SUM32W-CONST=0x%08X"%wa)
    print("  0x%06X len0x%X: diffs present. sum8 AB=%08X AD=%08X | crc32 AB=%08X AD=%08X | sum32w AB=%08X AD=%08X  %s"%(
        s,l,su_a,su_b,cr_a,cr_b,wa,wb,"  <<<"+";".join(flags) if flags else ""))
