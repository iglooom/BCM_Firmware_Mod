#!/usr/bin/env bash
# Post-flash check: did the probe come back as CMSIS-DAP v1 (HID)?
#
# Run this after flashing JTAGprobe-pico2-CMSIS-DAPv1-HID.uf2.  It separates the
# three things that can go wrong, so a failure points at one cause instead of
# leaving us guessing:
#
#   1. probe did not enumerate at all        -> flash did not take / bad UF2
#   2. enumerated but still VENDOR class     -> wrong firmware (still v2)
#   3. enumerated as HID but OpenOCD blind   -> permissions / hidraw access
#
# Usage: bash work/jtag/check_v1.sh
set -u
ROOT=/home/gl/Projects/ford/BCM/Research
OCD=$ROOT/work/jtag/openocd-xpc56/src/openocd

echo "== 1. USB enumeration =="
if ! lsusb -d 2e8a:000c >/dev/null 2>&1; then
    echo "   FAIL: probe 2e8a:000c not present."
    echo "   -> the flash did not take, or the board is still in BOOTSEL."
    exit 1
fi
lsusb -d 2e8a:000c | sed 's/^/   /'

echo ""
echo "== 2. interface 0 class (3 = HID/v1, 255 = vendor/v2) =="
CLS=$(lsusb -d 2e8a:000c -v 2>/dev/null | awk '/bInterfaceNumber +0/{f=1} f&&/bInterfaceClass/{print $2; exit}')
echo "   bInterfaceClass = ${CLS:-unknown}"
case "$CLS" in
    3)   echo "   -> HID: CMSIS-DAP v1.  This is what the xpc56 fork needs." ;;
    255) echo "   -> VENDOR: still CMSIS-DAP v2.  The new firmware did NOT take."
         echo "      Re-flash: hold BOOTSEL, plug in, copy the .uf2 to RPI-RP2."
         exit 1 ;;
    *)   echo "   -> unexpected; cannot continue confidently."; exit 1 ;;
esac

echo ""
echo "== 3. hidraw node + permissions =="
ls -l /dev/hidraw* 2>/dev/null | tail -3 | sed 's/^/   /'
echo "   (if OpenOCD says 'unable to find', a hidraw node exists but is not"
echo "    readable by $(whoami) - that is a udev/permissions issue, not firmware)"

echo ""
echo "== 4. does the xpc56 fork see it? =="
timeout 40 "$OCD" -f "$ROOT/work/jtag/xpc56_hid.cfg" -c 'echo "   --- targets ---"; targets; exit' 2>&1 \
    | grep -vE '^$' | sed 's/^/   /' | head -25
