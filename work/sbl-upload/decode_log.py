#!/usr/bin/env python3
"""Reassemble ISO-TP on 726 (tester) and 72E (ecu) from the flash log and print
the decoded UDS service exchange, so we replicate PROVEN on-wire behavior."""
import re
import os
HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(HERE,"..",".."))
lines=open(os.path.join(ROOT,"hscan_bcm_flash.log")).read().splitlines()
frames=[]
for l in lines:
    m=re.match(r'\(([\d.]+)\) can0 (726|72E)#([0-9A-Fa-f]+)',l)
    if m: frames.append((float(m.group(1)),m.group(2),bytes.fromhex(m.group(3))))

# ISO-TP reassembler per direction
class R:
    def __init__(s): s.buf=None; s.need=0
    def feed(s,d):
        pci=d[0]>>4
        if pci==0:   # SF
            n=d[0]&0xf; return d[1:1+n]
        if pci==1:   # FF
            s.need=((d[0]&0xf)<<8)|d[1]; s.buf=bytearray(d[2:]); return None
        if pci==2:   # CF
            if s.buf is None: return None
            s.buf+=d[1:]
            if len(s.buf)>=s.need:
                out=bytes(s.buf[:s.need]); s.buf=None; return out
            return None
        return None  # FC frame

rt=R(); re_=R()
t0=frames[0][0]
msgs=[]
for ts,cid,d in frames:
    r=(rt if cid=="726" else re_).feed(d)
    if r is not None:
        msgs.append((ts-t0, "REQ" if cid=="726" else "RSP", r))

def sname(b):
    return {0x10:"DiagSession",0x11:"ECUReset",0x22:"RDBI",0x27:"SecAccess",0x2E:"WDBI",
            0x31:"RoutineCtl",0x34:"ReqDownload",0x35:"ReqUpload",0x36:"TransferData",
            0x37:"ReqXferExit",0x3E:"TesterPresent"}.get(b, "")

# Print the first ~60 messages (SBL load happens early), compressing TransferData spam
last36=0
for t,role,m in msgs[:70]:
    sid=m[0]
    if role=="REQ" and sid==0x36:
        last36+=1
        if last36>3 and last36%20!=0:
            continue
    tag=sname(sid if role=="REQ" else (sid-0x40 if sid<0x7f else sid))
    hx=m.hex().upper()
    if len(hx)>48: hx=hx[:48]+f"...(+{len(m)-24}B)"
    print(f"{t:8.3f} {role:3} {tag:12} {hx}")
