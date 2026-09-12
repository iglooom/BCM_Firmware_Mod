#!/usr/bin/env python3
"""Assert nRESET (and optionally nTRST) on the target via CMSIS-DAP v1 (HID).

WHY DIRECT HID: the calandoa fork's JTAG scans are provably broken (BYPASS
shift fails at every length), so nothing it reports can be trusted.  But
DAP_SWJ_Pins is a *single short command* - it does not use the scan engine at
all - so driving it directly is both simpler and more trustworthy than any
target driver.

DAP_SWJ_Pins (0x10):
    request : 10 <pin_output> <pin_select> <wait_us:4 LE>
    response: 10 <pin_input>
  pin bits: 0=SWCLK/TCK 1=SWDIO/TMS 2=TDI 3=TDO 5=nTRST 7=nRESET

KEY POINT - this script verifies the pin is actually WIRED before claiming a
reset happened.  If the BCM does not connect nRESET to the probe header, the
read-back value will not follow what we drive, and we must say so instead of
reporting a reset we did not perform.  (An unwired line typically reads back
constant, or floats to whatever the on-board pull does.)
"""
import sys, time, glob

PIN_TCK, PIN_TMS, PIN_TDI, PIN_TDO, PIN_NTRST, PIN_NRESET = 0, 1, 2, 3, 5, 7
M_NRESET = 1 << PIN_NRESET
M_NTRST  = 1 << PIN_NTRST


def find_hidraw():
    """Locate the CMSIS-DAP hidraw node by checking its uevent for 2E8A:000C."""
    hits = []
    for node in sorted(glob.glob("/dev/hidraw*")):
        name = node.split("/")[-1]
        try:
            with open("/sys/class/hidraw/%s/device/uevent" % name) as f:
                u = f.read().upper()
        except OSError:
            continue
        if "2E8A" in u and "000C" in u:
            hits.append(node)
    return hits


class Dap:
    def __init__(self, node):
        self.f = open(node, "rb+", buffering=0)

    def cmd(self, payload):
        # Linux hidraw: prepend report ID 0, pad to 64-byte report.
        pkt = bytes([0x00]) + bytes(payload)
        pkt += b"\x00" * (65 - len(pkt))
        self.f.write(pkt)
        return self.f.read(64)

    def info(self):
        r = self.cmd([0x00, 0x01])          # DAP_Info: product/vendor string
        n = r[1]
        return r[2:2 + n].decode("ascii", "replace").strip("\x00")

    def connect_jtag(self):
        return self.cmd([0x02, 0x02])[1]    # DAP_Connect, port=2 (JTAG)

    def pins(self, out=0, sel=0, wait_us=0):
        w = wait_us & 0xFFFFFFFF
        r = self.cmd([0x10, out & 0xFF, sel & 0xFF,
                      w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF])
        return r[1]

    def read_pins(self):
        return self.pins(0, 0, 0)           # select=0 -> read only, drive nothing


def decode(v):
    return "TCK=%d TMS=%d TDI=%d TDO=%d nTRST=%d nRESET=%d" % (
        (v >> PIN_TCK) & 1, (v >> PIN_TMS) & 1, (v >> PIN_TDI) & 1,
        (v >> PIN_TDO) & 1, (v >> PIN_NTRST) & 1, (v >> PIN_NRESET) & 1)


def main():
    nodes = find_hidraw()
    if not nodes:
        print("FAIL: no CMSIS-DAP hidraw node (2E8A:000C) found.")
        return 1
    print("hidraw candidates: %s" % ", ".join(nodes))

    d = None
    for n in nodes:
        try:
            d = Dap(n)
            ident = d.info()
            print("using %s -> %r" % (n, ident))
            break
        except OSError as e:
            print("  %s not usable: %s" % (n, e))
            d = None
    if d is None:
        return 1

    d.connect_jtag()

    base = d.read_pins()
    print("\nbaseline pins: 0x%02X  %s" % (base, decode(base)))

    # --- is nRESET actually wired / drivable? -------------------------------
    print("\n=== nRESET drive test ===")
    lo = d.pins(out=0,        sel=M_NRESET, wait_us=20000)   # drive LOW
    print("  drive LOW  -> 0x%02X  nRESET=%d" % (lo, (lo >> PIN_NRESET) & 1))
    hi = d.pins(out=M_NRESET, sel=M_NRESET, wait_us=20000)   # drive HIGH
    print("  drive HIGH -> 0x%02X  nRESET=%d" % (hi, (hi >> PIN_NRESET) & 1))

    lo_b = (lo >> PIN_NRESET) & 1
    hi_b = (hi >> PIN_NRESET) & 1
    if lo_b == 0 and hi_b == 1:
        print("  => nRESET FOLLOWS the drive: the line is wired and controllable.")
        wired = True
    else:
        print("  => nRESET does NOT follow (low->%d, high->%d)." % (lo_b, hi_b))
        print("     Either the pin is not wired to the BCM on this harness, or the")
        print("     probe firmware does not read it back. A reset pulse may still")
        print("     reach the target, but we CANNOT confirm it here - do not claim")
        print("     a reset happened on the strength of this.")
        wired = False

    # --- the actual reset pulse --------------------------------------------
    hold_ms = 100
    print("\n=== asserting nRESET for %d ms ===" % hold_ms)
    d.pins(out=0, sel=M_NRESET, wait_us=1000)
    time.sleep(hold_ms / 1000.0)
    after = d.pins(out=M_NRESET, sel=M_NRESET, wait_us=1000)
    print("  released; pins now 0x%02X  %s" % (after, decode(after)))

    # Stop driving, so the board's own pull-up owns the line again.
    time.sleep(0.05)
    d.pins(out=0, sel=0, wait_us=0)
    final = d.read_pins()
    print("  released to board: 0x%02X  %s" % (final, decode(final)))

    print("\nwired_and_verified=%s" % wired)
    return 0


if __name__ == "__main__":
    sys.exit(main())
