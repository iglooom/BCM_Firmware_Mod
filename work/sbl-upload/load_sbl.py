#!/usr/bin/env python3
"""Load the stock DV6T-14C097-AB SBL into the BCM RAM over UDS, replicating the
EXACT proven sequence from hscan_bcm_flash.log, then leave the SBL running.

Sequence (proven): 10 02 -> 27 01/02 -> 3E 80 -> for each VBF block:
  34 00 44 <addr4> <len4> -> 74 20 <chunk2> -> 36 <bc> <data...> (chunked) -> 37 -> 77 <crc16>
then 31 01 0301 <callAddr4> to start SBL.
"""
import os, sys, time, struct
from uds import open_isotp, req

HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(HERE,"..",".."))
DEFAULT_VBF=os.path.join(ROOT,"DV6T-14C097-AB.vbf")
SECRET_L1=bytes.fromhex("64000B0C59")

def kfs(seed3, secret=SECRET_L1):
    s1,s2,s3,s4,s5=secret
    seed_int=(seed3[0]<<16)+(seed3[1]<<8)+seed3[2]
    or_ed=((seed_int&0xFF0000)>>16)|(seed_int&0xFF00)|(s1<<24)|(seed_int&0xff)<<16
    m=0xc541a9
    for i in range(32):
        a=((or_ed>>i)&1 ^ m&1)<<23; v=a|(m>>1)
        m=v&0xEF6FD7|((((v&0x100000)>>20)^((v&0x800000)>>23))<<20)|(((((m>>1)&0x8000)>>15)^((v&0x800000)>>23))<<15)|(((((m>>1)&0x1000)>>12)^((v&0x800000)>>23))<<12)|32*((((m>>1)&0x20)>>5)^((v&0x800000)>>23))|8*((((m>>1)&8)>>3)^((v&0x800000)>>23))
    for j in range(32):
        a=((((s5<<24)|(s4<<16)|s2|(s3<<8))>>j)&1 ^ m&1)<<23; v=a|(m>>1)
        m=v&0xEF6FD7|((((v&0x100000)>>20)^((v&0x800000)>>23))<<20)|(((((m>>1)&0x8000)>>15)^((v&0x800000)>>23))<<15)|(((((m>>1)&0x1000)>>12)^((v&0x800000)>>23))<<12)|32*((((m>>1)&0x20)>>5)^((v&0x800000)>>23))|8*((((m>>1)&8)>>3)^((v&0x800000)>>23))
    key=((m&0xF0000)>>16)|16*(m&0xF)|((((m&0xF00000)>>20)|((m&0xF000)>>8))<<8)|((m&0xFF0)>>4<<16)
    return bytes([(key&0xff0000)>>16,(key&0xff00)>>8,key&0xff])

def parse_vbf(path):
    d=open(path,'rb').read()
    i=d.find(b'header'); depth=0; j=d.find(b'{',i)
    while True:
        c=d[j:j+1]
        if c==b'{':depth+=1
        elif c==b'}':
            depth-=1
            if depth==0: hend=j+1;break
        j+=1
    import re as _re
    hdr=d[:hend].decode('latin1')
    call=int(_re.search(r'call\s*=\s*0x([0-9A-Fa-f]+)',hdr).group(1),16)
    off=hend
    while d[off] in (0x0d,0x0a,0x20,0x09): off+=1
    p=off; blks=[]
    while p+8<=len(d):
        s,l=struct.unpack('>II',d[p:p+8])
        if l==0 or p+8+l+2>len(d): break
        data=d[p+8:p+8+l]; crc=struct.unpack('>H',d[p+8+l:p+8+l+2])[0]
        blks.append((s,l,data,crc)); p=p+8+l+2
    return call, blks

def expect(r, pfx, what):
    ok = r is not None and r[0]==pfx
    print(f"  {'OK ' if ok else 'ERR'} {what}: {r.hex().upper() if r else None}")
    if not ok: raise SystemExit(f"FAILED at {what}")
    return r

def main():
    vbf = sys.argv[1] if len(sys.argv)>1 else DEFAULT_VBF
    call, blks = parse_vbf(vbf)
    print("VBF:",vbf)
    print(f"VBF call=0x{call:08X}, {len(blks)} blocks")
    s=open_isotp()
    # wake
    req(s,"3E00",timeout=1.0); time.sleep(0.05)
    expect(req(s,"1002",timeout=2.0), 0x50, "DiagSession 10 02")
    time.sleep(0.1)
    r=expect(req(s,"2701",timeout=2.0), 0x67, "Seed 27 01")
    key=kfs(list(r[2:5]))
    print(f"    seed {bytes(r[2:5]).hex().upper()} -> key {key.hex().upper()}")
    expect(req(s,"2702"+key.hex(),timeout=2.0), 0x67, "Key 27 02")
    req(s,"3E80",timeout=1.0)
    # download each block
    for bi,(addr,length,data,crc) in enumerate(blks):
        rd = "34" + "00" + "44" + struct.pack(">I",addr).hex() + struct.pack(">I",length).hex()
        r=expect(req(s,rd,timeout=3.0), 0x74, f"blk{bi} ReqDownload @0x{addr:08X} len0x{length:X}")
        # chunk size from 74 20 <hi><lo> or 74 10 <n>
        if r[1]==0x20: chunk=(r[2]<<8)|r[3]
        elif r[1]==0x10: chunk=r[2]
        else: chunk=0x100
        chunk-=2  # minus SID+blockcounter overhead per tool
        bc=1; off=0
        while off<length:
            piece=data[off:off+chunk]
            msg=bytes([0x36,bc&0xff])+piece
            rr=req(s, msg.hex(), timeout=5.0)
            if rr is None or rr[0]!=0x76:
                print(f"    ERR TransferData bc={bc}: {rr.hex().upper() if rr else None}"); raise SystemExit(1)
            off+=len(piece); bc=(bc+1)&0xff
        r=expect(req(s,"37",timeout=3.0), 0x77, f"blk{bi} ReqXferExit (crc echo {crc:04X})")
    # start SBL
    ca = "3101" + "0301" + struct.pack(">I",call).hex()
    r=req(s, ca, timeout=3.0)
    print(f"  CallAddress 31 01 0301 {call:08X}: {r.hex().upper() if r else None}")
    if r and r[0]==0x71:
        print("*** SBL LOADED AND STARTED ***")
    else:
        print("!!! SBL start returned unexpected — may still be running, check with probe")

if __name__=="__main__":
    main()
