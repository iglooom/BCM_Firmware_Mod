#!/usr/bin/env python3
import struct
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
for f,exp in (("JV6T-14C094-AB.VBF",0x6288),("JV6T-14C094-AD.VBF",0x7572),
              ("work/out_resplus/JV6T-14C094-AD_RESPLUS.VBF",None)):
    buf,lo=flat(ROOT+"/"+f)
    stored=struct.unpack_from(">H",buf,0x13FFFE-lo)[0]
    calc=sum(buf[0:0x13FFFE-lo])&0xFFFF
    print("%-45s stored=0x%04X calc=0x%04X %s"%(f.split('/')[-1],stored,calc,
          "OK" if stored==calc else ("<<< MISMATCH (this is why BCM rejected it!)" )))
