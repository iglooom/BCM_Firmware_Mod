#!/usr/bin/env python3
"""Probe the RUNNING stock SBL: try 0x35 RequestUpload at various addresses and
observe. Must be run right after load_sbl.py (SBL live in RAM)."""
import sys, time, struct
from uds import open_isotp, req

def ru(s, addr, size, fmt=0x00, alf=0x44):
    msg = bytes([0x35,fmt,alf])+struct.pack(">I",addr)+struct.pack(">I",size)
    return req(s, msg.hex(), timeout=3.0)

def td(s, bc):
    return req(s, bytes([0x36,bc&0xff]).hex(), timeout=3.0)

s=open_isotp()
# keep alive
req(s,"3E80",timeout=1.0)
print("== Probe RequestUpload (0x35) on running SBL ==")
for addr,size in [(0x00000000,0x10),(0x00C00000,0x10),(0x0000EC00,0x10),(0x40002000,0x10)]:
    r=ru(s,addr,size)
    print(f"  35 @0x{addr:08X} len0x{size:X} -> {r.hex().upper() if r else None}")
    if r and r[0]==0x75:
        # try to pull first block
        t=td(s,1)
        print(f"      36 01 -> {t.hex().upper() if t else None}")
        req(s,"37",timeout=2.0)
    time.sleep(0.1)
