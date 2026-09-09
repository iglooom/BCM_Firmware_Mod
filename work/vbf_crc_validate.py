#!/usr/bin/env python3
"""Validate our VBF CRC algorithms against the untouched OEM containers.
Per the patching skill: never trust a repair algorithm until it reproduces the
original container's own checksums byte-exact."""
import struct, zlib, re, hashlib, glob

def crc16_ccitt_false(data):
    crc=0xFFFF
    for b in data:
        crc ^= b<<8
        for _ in range(8):
            crc = ((crc<<1)^0x1021) & 0xFFFF if (crc & 0x8000) else (crc<<1)&0xFFFF
    return crc

def find_header_end(d):
    i=d.find(b'header'); depth=0; j=d.find(b'{',i)
    while j<len(d):
        c=d[j]
        if c==0x7b: depth+=1
        elif c==0x7d:
            depth-=1
            if depth==0: return j+1
        j+=1
    raise ValueError("no header end")

def parse(path):
    d=open(path,'rb').read()
    hdr=d[:find_header_end(d)].decode('latin1')
    off=find_header_end(d)
    while off<len(d) and d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    data_start=off
    blocks=[]; p=off
    while p+8<=len(d):
        start,length=struct.unpack('>II',d[p:p+8])
        if length==0 or p+8+length+2>len(d): break
        bdata=d[p+8:p+8+length]
        crc=struct.unpack('>H',d[p+8+length:p+8+length+2])[0]
        blocks.append((p,start,length,bdata,crc))
        p=p+8+length+2
    return d,hdr,data_start,blocks,p

for path in sorted(glob.glob("/home/gl/Projects/ford/BCM/Research/*.VBF")):
    d,hdr,ds,blocks,end=parse(path)
    m=re.search(r'file_checksum\s*=\s*0x([0-9A-Fa-f]+)',hdr)
    hdr_fc=int(m.group(1),16) if m else None
    name=path.split('/')[-1]
    print(f"\n=== {name}  sha256={hashlib.sha256(d).hexdigest()[:16]}  trailing={len(d)-end}")
    all_ok=True
    for (recoff,start,length,bdata,crc) in blocks:
        calc=crc16_ccitt_false(bdata)
        ok = calc==crc
        all_ok &= ok
        print(f"  block load=0x{start:08X} len=0x{length:X} crc16 stored=0x{crc:04X} calc=0x{calc:04X} {'OK' if ok else 'FAIL'}")
    # file crc32 over everything from first block's start-addr field to EOF
    fc_calc = zlib.crc32(d[ds:]) & 0xFFFFFFFF
    print(f"  file_checksum header=0x{hdr_fc:08X} calc(zlib,crc32 from 0x{ds:X}..EOF)=0x{fc_calc:08X} {'OK' if hdr_fc==fc_calc else 'MISMATCH'}")
