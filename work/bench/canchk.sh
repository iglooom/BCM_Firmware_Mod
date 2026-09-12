#!/usr/bin/env bash
# Is the BCM on can0 answering UDS after the JTAG session?
cd /home/gl/Projects/ford/BCM/Research
timeout 8 candump -L can0 > /tmp/canchk.log 2>&1 &
CAP=$!
sleep 0.5
for i in $(seq 1 14); do
    cansend can0 726#023E00000000000000 2>/dev/null
    sleep 0.4
done
sleep 1
kill $CAP 2>/dev/null
wait $CAP 2>/dev/null
echo "  frames captured : $(wc -l < /tmp/canchk.log)"
echo "  responses (72E) : $(grep -c '72E#' /tmp/canchk.log)"
grep '72E#' /tmp/canchk.log | head -3
