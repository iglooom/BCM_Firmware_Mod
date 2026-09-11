#!/usr/bin/env python3
"""Capture raw can0 traffic while loading/running the dump probe VBF; search all
CAN IDs for the DUMPTEST marker, including ISO-TP reassembly."""
import socket, struct, subprocess, time, select, os
HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(HERE,"..",".."))
VBF=ROOT+"/work/sbl-upload/DV6T-14C097-AB_dump-probe.VBF"
LOG=ROOT+"/work/sbl-upload/probe_capture.log"
CAN_RAW=1
rs=socket.socket(socket.AF_CAN,socket.SOCK_RAW,CAN_RAW)
rs.bind(("can0",)); rs.setblocking(False)
cmd=["python3",ROOT+"/work/sbl-upload/load_sbl.py",VBF]
print("starting:"," ".join(cmd))
p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
t0=time.time(); frames=[]; proc_done=None
while True:
    now=time.time()
    if p.poll() is not None and proc_done is None: proc_done=now
    if proc_done is not None and now-proc_done>4.0: break
    if now-t0>90:
        p.kill(); raise SystemExit("timeout")
    rr,_,_=select.select([rs],[],[],0.02)
    if rr:
        raw=rs.recv(16)
        canid,dlc,data=struct.unpack("=IB3x8s",raw)
        canid &= 0x1fffffff; frames.append((now-t0,canid,data[:dlc]))
out=p.stdout.read() if p.stdout else ""
print(out)
with open(LOG,"w") as f:
    for t,cid,d in frames: f.write(f"({t:.6f}) can0 {cid:03X}#{d.hex().upper()}\n")
print("captured",len(frames),"frames ->",LOG)
# direct frame print around likely post-call (last 80 diagnostic-ish frames)
interesting=[x for x in frames if x[1] in (0x726,0x72e) or b"DUMP" in x[2] or b"TEST" in x[2]]
print("last interesting frames:")
for t,cid,d in interesting[-50:]: print(f"  {t:8.3f} {cid:03X}#{d.hex().upper()}")
# ISO-TP reassemble independently for every CAN ID.
state={}; messages=[]
for t,cid,d in frames:
    if not d: continue
    pci=d[0]>>4
    if pci==0:
        n=d[0]&0xf; messages.append((t,cid,d[1:1+n]))
    elif pci==1:
        n=((d[0]&0xf)<<8)|d[1]; state[cid]=[n,bytearray(d[2:])]
    elif pci==2 and cid in state:
        n,b=state[cid]; b+=d[1:]
        if len(b)>=n:
            messages.append((t,cid,bytes(b[:n])))
            del state[cid]
found=False
# Direct-probe success is exact raw CAN frame 0x5A5#44554D5054455354.
# Do NOT count the same bytes inside tester ID 0x726 while downloading the VBF.
for t,cid,d in frames:
    if cid==0x5A5 and d==b"DUMPTEST":
        print(f"*** FOUND ECU DIRECT FRAME: t={t:.3f} 5A5#{d.hex().upper()} ***")
        found=True
print("RESULT:","PASS marker transmitted" if found else "FAIL marker not observed")
raise SystemExit(0 if found else 2)
