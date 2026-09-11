#!/usr/bin/env python3
import sys, time
from uds import open_isotp, req

def kfs(seed3, secret):
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

SECRET_L1=bytes.fromhex("64000B0C59")
s=open_isotp()
req(s,"3E00",timeout=1.0); time.sleep(0.05)
r=req(s,"1002",timeout=2.0); print("Session 10 02 ->", r.hex().upper() if r else None)
time.sleep(0.1)
r=req(s,"2701",timeout=2.0); print("Seed req 27 01 ->", r.hex().upper() if r else None)
if r and r[0]==0x67:
    seed=list(r[2:5]); key=kfs(seed,SECRET_L1)
    print("  seed:", bytes(seed).hex().upper(), " key:", key.hex().upper())
    r2=req(s,"2702"+key.hex(),timeout=2.0); print("Key send 27 02 ->", r2.hex().upper() if r2 else None)
    if r2 and r2[0]==0x67: print("  *** SECURITY ACCESS GRANTED ***")
