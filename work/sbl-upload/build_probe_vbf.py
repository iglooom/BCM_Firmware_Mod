#!/usr/bin/env python3
"""Build DV6T-14C097-AB_dump-probe.VBF by preserving every OEM block byte-exact,
appending the probe as block 7, changing call address, and repairing CRC16/CRC32."""
import json, os, re, struct, zlib, hashlib
HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(HERE,"..",".."))
SRC=os.path.join(ROOT,"DV6T-14C097-AB.vbf")
OUT=os.path.join(HERE,"DV6T-14C097-AB_dump-probe.VBF")
BLOB=json.load(open(os.path.join(HERE,"probe_blob.json")))
NEW_ADDR=int(BLOB["address"]); NEW_DATA=bytes(BLOB["blob"])

def crc16(d):
    c=0xffff
    for b in d:
        c^=b<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xffff if c&0x8000 else (c<<1)&0xffff
    return c

def header_end(d):
    i=d.find(b"header"); j=d.find(b"{",i); depth=0
    while j<len(d):
        if d[j]==0x7b: depth+=1
        elif d[j]==0x7d:
            depth-=1
            if depth==0: return j+1
        j+=1
    raise ValueError("header end")

d=open(SRC,"rb").read(); hend=header_end(d)
hdr=d[:hend].decode("latin1")
off=hend
while d[off] in (9,10,13,32): off+=1
blocks=[]; p=off
while p+8<=len(d):
    a,n=struct.unpack(">II",d[p:p+8])
    if n==0 or p+8+n+2>len(d): break
    blocks.append((a,d[p+8:p+8+n])); p+=8+n+2
assert p==len(d) and len(blocks)==6
# Prevent overlap.
for a,b in blocks:
    assert NEW_ADDR+len(NEW_DATA)<=a or NEW_ADDR>=a+len(b), (hex(a),len(b))
blocks.append((NEW_ADDR,NEW_DATA))
# Update human-readable fields explicitly. file checksum placeholder has same width.
hdr=re.sub(r'call\s*=\s*0x[0-9A-Fa-f]+;',f'call = 0x{NEW_ADDR:08X};',hdr)
hdr=re.sub(r'// Blocks:\s*\d+',f'// Blocks:   {len(blocks)}',hdr)
hdr=re.sub(r'// Bytes:\s*\d+',f'// Bytes:    {sum(len(b) for _,b in blocks)}',hdr)
hdr=re.sub(r'file_checksum\s*=\s*0x[0-9A-Fa-f]+;', 'file_checksum = 0x00000000;', hdr)
# Preserve original whitespace between header and block data.
sep=d[hend:off]
body=bytearray()
for a,b in blocks:
    body+=struct.pack(">II",a,len(b))+b+struct.pack(">H",crc16(b))
raw=hdr.encode("latin1")+sep+body
# CRC32 starts at first block start-addr field.
ds=len(hdr.encode("latin1"))+len(sep)
fc=zlib.crc32(raw[ds:])&0xffffffff
raw=re.sub(rb'file_checksum\s*=\s*0x00000000;',f'file_checksum = 0x{fc:08X};'.encode(),raw,count=1)
open(OUT,"wb").write(raw)
print("wrote",OUT)
print("size",len(raw),"sha256",hashlib.sha256(raw).hexdigest())
print("blocks",len(blocks),"data bytes",sum(len(b) for _,b in blocks),"file_crc32",f"0x{fc:08X}")
for i,(a,b) in enumerate(blocks): print(f"  {i}: 0x{a:08X} len0x{len(b):X} crc16=0x{crc16(b):04X}")
