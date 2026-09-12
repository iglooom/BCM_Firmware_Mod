#!/usr/bin/env bash
# Sweep OCR values and see which (if any) HOLDS the core in debug mode.
#
# Finding under test (jtag_bringup 6.9): after xpc56_debug_enter() the OnCE
# status register shows DEBUG (bit5) set for exactly ONE scan, then clear
# forever - so every CPUSCR data access runs with the core out of debug mode
# and returns zeros.
#
# Candidate (a): the OCR value upstream writes, BIT(2)|BIT(1)|BIT(0) = 0x7,
# omits whatever keeps debug asserted on this part.
#
# Each run: fresh openocd, one OCR value, 8 OSR polls with nothing else
# happening, then nRESET + CAN check so the ECU is never left wedged.
#
# NOTE: nRESET does NOT reliably recover a deep halt (6.4.1). The CAN check
# after each trial reports honestly; if it stays at 0 the run is stopped so a
# human can power-cycle rather than piling more trials onto a wedged core.
set -u
ROOT=/home/gl/Projects/ford/BCM/Research
cd "$ROOT"
OCD=work/jtag/openocd-xpc56/src/openocd

reset_pulse() {
    .venv/bin/python3 - <<'PY'
import glob, time
M = 1 << 7
def node():
    for n in sorted(glob.glob('/dev/hidraw*')):
        nm = n.split('/')[-1]
        try:
            u = open('/sys/class/hidraw/%s/device/uevent' % nm).read().upper()
        except OSError:
            continue
        if '2E8A' in u and '000C' in u:
            return n
n = node()
if not n:
    raise SystemExit(0)
f = open(n, 'rb+', buffering=0)
def cmd(p):
    pkt = bytes([0]) + bytes(p); pkt += b'\x00' * (65 - len(pkt))
    f.write(pkt); return f.read(64)
cmd([0x02, 0x02])
def pins(out=0, sel=0):
    return cmd([0x10, out & 0xFF, sel & 0xFF, 0, 0, 0, 0])[1]
pins(0, M); time.sleep(0.1); pins(M, M); time.sleep(2.0)
PY
}

alive() {
    bash work/bench/canchk.sh 2>/dev/null | awk -F: '/responses/{gsub(/ /,"",$2); print $2}'
}

echo "=== pre-flight: BCM alive? ==="
n=$(alive); echo "   responses: $n"
if [ "${n:-0}" = "0" ]; then
    echo "   BCM is not responding - power-cycle before running this."
    exit 1
fi

for OCR in "$@"; do
    echo ""
    echo "############ OCR = $OCR ############"
    XPC56_OCR="$OCR" timeout 90 "$OCD" -f work/jtag/xpc56_hid.cfg -c 'exit' 2>&1 \
        | grep -E 'OCR written|poll [0-7] :|RESULT OCR' | head -12
    reset_pulse
    n=$(alive)
    echo "   after nRESET -> CAN responses: $n"
    if [ "${n:-0}" = "0" ]; then
        echo "   *** ECU did not recover - stopping. Power-cycle required. ***"
        exit 2
    fi
done
echo ""
echo "=== sweep complete, ECU alive ==="
