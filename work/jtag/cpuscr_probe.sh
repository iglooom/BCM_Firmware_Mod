#!/usr/bin/env bash
# Capture the raw CPUSCR chain on a halted core, then ALWAYS recover via nRESET.
#
# Safety: the xpc56 fork halts the CPU at `init` and cannot resume it (see
# docs/jtag_bringup.md 6.2). nRESET recovery is proven (6.4), so this script
# runs the reset unconditionally in a trap - the ECU must never be left halted.
set -u
ROOT=/home/gl/Projects/ford/BCM/Research
cd "$ROOT"

recover() {
    echo ""
    echo "=== RECOVERING via nRESET (unconditional) ==="
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
    print("   no probe found - CANNOT RECOVER, power-cycle required")
    raise SystemExit(1)
f = open(n, 'rb+', buffering=0)
def cmd(p):
    pkt = bytes([0]) + bytes(p); pkt += b'\x00' * (65 - len(pkt))
    f.write(pkt); return f.read(64)
cmd([0x02, 0x02])
def pins(out=0, sel=0):
    return cmd([0x10, out & 0xFF, sel & 0xFF, 0, 0, 0, 0])[1]
pins(0, M); time.sleep(0.05); pins(M, M)
time.sleep(1.5)
print("   pins after reset: 0x%02X" % pins())
PY
    sleep 1
    echo "   CAN check:"
    bash work/bench/canchk.sh | sed 's/^/   /'
}
trap recover EXIT

echo "=== pre-halt CAN ==="
bash work/bench/canchk.sh | sed 's/^/   /'

echo ""
echo "=== attaching (init halts the core) + capturing CPUSCR ==="
timeout 90 work/jtag/openocd-xpc56/src/openocd \
    -f work/jtag/xpc56_hid.cfg \
    -c 'mdw 0x000de278 1; exit' 2>&1 \
    | grep -E 'CPUSCR|DBG|0x000de278|osr:|tap/device' | head -40
