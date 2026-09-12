#!/bin/bash
# Isolate a single RKE command nibble and record the 0x3A response.
#
# The sweep's per-slice attribution is confounded because d3 is a LEVEL that
# persists into the next slice.  The unambiguous marker is the EXECUTE STROBE
# (d1 bit6), which is a one-shot emitted at the moment of actuation.  This
# script therefore drives ONE nibble in isolation, from a settled idle bus, and
# reports the strobed payloads only.
#
# usage: one_nibble.sh <nibble-dec> [presses]
set -u
NIB=${1:-3}
N=${2:-3}
STAMP=$(date +%Y%m%dT%H%M%S)
TAG="nib${NIB}"
LOG="logs/${STAMP}_${TAG}.log"
mkdir -p logs

candump -ta can1 > "$LOG" 2>/dev/null &
CAP=$!
sleep 0.5

python3 - "$NIB" "$N" <<'PY'
import socket, struct, sys, time
nib = int(sys.argv[1]); n = int(sys.argv[2])
s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW); s.bind(("can1",))
def tx(cid, d):
    s.send(struct.pack("=IB3x8s", cid, len(d), bytes(d).ljust(8, b"\0")))
IDLE = [0x02,0x17,0x00,0x00,0x02,0x00,0x20,0x00]      # release word 0x2000
def idle(secs, ko=True):
    f = list(IDLE)
    if ko: f[1] |= 0x80
    end = time.time()+secs
    while time.time() < end:
        tx(0x100, f); time.sleep(0.06)
def press(nib, secs, ko=True):
    f = list(IDLE); f[1] |= 0x80 if ko else 0
    f[6] = (0x1F << 3) & 0xFF          # code_hi as seen on the wire
    f[7] = nib & 0xFF
    end = time.time()+secs
    while time.time() < end:
        tx(0x100, f); time.sleep(0.06)
idle(2.5)
for k in range(n):
    press(nib, 0.4); idle(1.6)
idle(1.5)
PY

sleep 0.5
kill -INT $CAP 2>/dev/null
wait $CAP 2>/dev/null

echo "=== nibble $NIB : distinct 0x03A payloads ==="
grep -w '03A' "$LOG" | sed 's/.*\[8\]  //' | sort | uniq -c | sort -rn
echo "=== STROBED frames only (d1 bit6) - the unambiguous actuation marker ==="
grep -w '03A' "$LOG" | sed 's/.*\[8\]  //' \
  | awk '{d=strtonum("0x" $2); if (and(d,0x40)) print}' | sort | uniq -c
echo "log: $LOG"
