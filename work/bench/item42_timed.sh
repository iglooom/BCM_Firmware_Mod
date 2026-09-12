#!/bin/bash
# Item 42 - the timed feature, as a FALSIFIABLE PREDICTION.
#
# Static claim (layer 36 / script 250): FUN_0008D4DA case 3 starts a timer
#   DAT_40008E46 = DAT_4000588F * 0x32 ; DAT_40008DF0 += 10 per tick
# and sets DAT_40002E44 |= 0x40.  Script 250 resolved that cell through the
# decoded TX tables to FIVE frame bytes:
#     HS 0x380 d4 | MS 0x1A8 d0 | MS 0x1B0 d2 | MS 0x290 d0 | MS 0x370 d4
#
# PREDICTION: driving RKE nibble 3 (which reaches d3=06 and actuates NO relay)
# must produce a TIMED change in those bytes and (ideally) nowhere else.
# If the changed bytes are NOT in that set, the static resolution is WRONG and
# 250 must be redone.  That is the point - this can fail.
#
# Captures BOTH buses, brackets the stimulus with quiet windows, and diffs
# every byte of every frame between windows.  No audio, so room noise is fine.
set -u
STAMP=$(date +%Y%m%dT%H%M%S)
mkdir -p logs
HS="logs/${STAMP}_t42_hs.log"
MS="logs/${STAMP}_t42_ms.log"

candump -ta can0 > "$HS" 2>/dev/null &
C0=$!
candump -ta can1 > "$MS" 2>/dev/null &
C1=$!
sleep 0.5

python3 - <<'PY'
import socket, struct, time
s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW); s.bind(("can1",))
def tx(cid, d): s.send(struct.pack("=IB3x8s", cid, len(d), bytes(d).ljust(8, b"\0")))
IDLE = [0x02,0x17,0x00,0x00,0x02,0x00,0x20,0x00]
def idle(sec):
    f=list(IDLE); f[1]|=0x80; e=time.time()+sec
    while time.time()<e: tx(0x100,f); time.sleep(0.06)
def press(nib,sec):
    f=list(IDLE); f[1]|=0x80; f[6]=(0x1F<<3)&0xFF; f[7]=nib; e=time.time()+sec
    while time.time()<e: tx(0x100,f); time.sleep(0.06)
print("MARK baseline %.6f"%time.time()); idle(4.0)
print("MARK press    %.6f"%time.time()); press(3,0.4)
print("MARK after    %.6f"%time.time()); idle(12.0)
print("MARK end      %.6f"%time.time())
PY

sleep 0.5
kill -INT $C0 $C1 2>/dev/null
wait $C0 2>/dev/null; wait $C1 2>/dev/null
echo "HS=$HS"
echo "MS=$MS"
