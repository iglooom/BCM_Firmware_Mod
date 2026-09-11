#!/usr/bin/env python3
"""Verify probe VBF structure, OEM block preservation, CRCs, call address,
and appended probe bytes."""
import hashlib, json, os, re, struct, zlib
HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(HERE,"..",".."))
OEM=os.path.join(ROOT,"DV6T-14C097-AB.vbf")
MOD=os.path.join(HERE,"DV6T-14C097-AB_dump-probe.VBF")

def crc16(d):
    c=0xffff
    for b in d:
        c^=b<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xffff if c&0x8000 else (c<<1)&0xffff
    return c

def parse(path):
    raw=open(path,"rb").read(); i=raw.find(b"header"); j=raw.find(b"{",i); dep=0
    while j<len(raw):
        if raw[j]==0x7b: dep+=1
        elif raw[j]==0x7d:
            dep-=1
            if dep==0: hend=j+1; break
        j+=1
    hdr=raw[:hend].decode("latin1"); p=hend
    while raw[p] in (9,10,13,32): p+=1
    ds=p; out=[]
    while p+8<=len(raw):
        a,n=struct.unpack(">II",raw[p:p+8]); assert n and p+8+n+2<=len(raw)
        d=raw[p+8:p+8+n]; stored=struct.unpack(">H",raw[p+8+n:p+10+n])[0]
        assert crc16(d)==stored
        out.append((a,d,stored)); p+=10+n
    assert p==len(raw)
    fm=re.search(r'file_checksum\s*=\s*0x([0-9A-Fa-f]+)',hdr); assert fm
    fc=int(fm.group(1),16); assert zlib.crc32(raw[ds:])&0xffffffff==fc
    cm=re.search(r'call\s*=\s*0x([0-9A-Fa-f]+)',hdr); assert cm
    call=int(cm.group(1),16)
    return raw,hdr,call,out,fc

oraw,oh,oc,ob,of=parse(OEM); mraw,mh,mc,mb,mf=parse(MOD)
assert len(ob)==6 and len(mb)==7 and mc==0x40006000
for i in range(6): assert ob[i]==mb[i],f"OEM block{i} changed"
blob=bytes(json.load(open(os.path.join(HERE,"probe_blob.json")))["blob"])
assert mb[6][0]==0x40006000 and mb[6][1]==blob
assert "Blocks:   7" in mh
print("PASS probe VBF")
print("  call=0x%08X blocks=%d file_crc32=0x%08X"%(mc,len(mb),mf))
print("  OEM six blocks preserved byte-exact; all CRC16 + file CRC32 valid")
print("  probe block=0x%08X len=0x%X crc16=0x%04X"%(mb[6][0],len(blob),mb[6][2]))
print("  sha256",hashlib.sha256(mraw).hexdigest())