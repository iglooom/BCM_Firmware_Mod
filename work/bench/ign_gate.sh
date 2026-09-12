#!/bin/bash
# Ignition-gate test - open item 30 / README §8 item 1.
#
# Floods MS-CAN 0x3A0 with a chosen d0 while pressing LOCK on the simulated
# RFA, and reports the observable (0x3A d3 + the d1 bit6 execute strobe).
#
# The two hypotheses differ observably:
#   a GATE exists      -> d3 never reaches 01 with ignition Run
#   NO PATH exists     -> d3 reaches 01 but d1 bit6 never strobes
#
# usage: ign_gate.sh <d0hex> <tag>     d0: 41 = Run, 11 = off (bench baseline)
set -u
D0=${1:-41}
TAG=${2:-ign}
STAMP=$(date +%Y%m%dT%H%M%S)
LOG="logs/${STAMP}_${TAG}.log"
mkdir -p logs

candump -ta can1 > "$LOG" 2>/dev/null &
CAP=$!
sleep 0.5

# ignition flood at 20 ms for the whole trial
( for i in $(seq 1 900); do cansend can1 "3A0#${D0}00000000000000" 2>/dev/null; sleep 0.02; done ) &
IGN=$!

sleep 2
python3 rfa_sim.py press --cmd lock --n 4 --key-outside > "logs/${STAMP}_${TAG}_press.json" 2>&1

kill $IGN 2>/dev/null
sleep 0.5
kill -INT $CAP 2>/dev/null
wait $CAP 2>/dev/null

echo "=== log: $LOG ==="
echo "--- 0x3A0 on the wire (what the BCM sees) ---"
grep -w '3A0' "$LOG" | sed 's/.*\[8\]  //' | sort | uniq -c | sort -rn | head -4
echo "--- 0x03A distinct payloads (the observable) ---"
grep -w '03A' "$LOG" | sed 's/.*\[8\]  //' | sort | uniq -c | sort -rn | head -8
echo "--- d3 values (the lock command) ---"
grep -w '03A' "$LOG" | sed 's/.*\[8\]  //' | awk '{print $4}' | sort | uniq -c
echo "--- frames with the d1 bit6 execute strobe ---"
grep -w '03A' "$LOG" | sed 's/.*\[8\]  //' \
  | awk '{d=strtonum("0x" $2); if (and(d,0x40)) print}' | sort | uniq -c
