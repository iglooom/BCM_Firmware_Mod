#!/usr/bin/env python3
"""Is nRESET actually LOW *while* we hold it, and does the BCM see it?

reset_escalate.py only sampled the pin AFTER release, so a failed recovery
could mean either (a) the reset genuinely does not clear OnCE debug state, or
(b) the line never went low at all.  Distinguish them by reading the pin
MID-PULSE - and, critically, by checking whether the line is being pulled back
up by the target (proving a real electrical connection, not just the probe
talking to itself).

Also samples TDO during the hold: on a real reset the TAP/boundary state can
move, so a change there is corroborating evidence the chip saw something.
"""
import glob, sys, time

PIN = {"TCK": 0, "TMS": 1, "TDI": 2, "TDO": 3, "nTRST": 5, "nRESET": 7}
M_NRESET = 1 << PIN["nRESET"]


def node():
    for n in sorted(glob.glob("/dev/hidraw*")):
        nm = n.split("/")[-1]
        try:
            u = open("/sys/class/hidraw/%s/device/uevent" % nm).read().upper()
        except OSError:
            continue
        if "2E8A" in u and "000C" in u:
            return n
    return None


class Dap:
    def __init__(self, n):
        self.f = open(n, "rb+", buffering=0)

    def cmd(self, p):
        pkt = bytes([0x00]) + bytes(p)
        pkt += b"\x00" * (65 - len(pkt))
        self.f.write(pkt)
        return self.f.read(64)

    def connect(self):
        return self.cmd([0x02, 0x02])[1]

    def pins(self, out=0, sel=0, wait_us=0):
        w = wait_us & 0xFFFFFFFF
        return self.cmd([0x10, out & 0xFF, sel & 0xFF,
                         w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF])[1]


def dec(v):
    return " ".join("%s=%d" % (k, (v >> b) & 1) for k, b in PIN.items())


def main():
    n = node()
    if not n:
        print("no probe")
        return 1
    d = Dap(n)
    d.connect()

    idle = d.pins()
    print("idle                 : 0x%02X  %s" % (idle, dec(idle)))

    # Assert and sample WHILE holding (select=nRESET, value=0 -> drive low).
    d.pins(0, M_NRESET)
    mid = [d.pins(0, M_NRESET) for _ in range(3)]
    print("held LOW (3 samples) : %s" % " ".join("0x%02X" % m for m in mid))
    print("                       %s" % dec(mid[-1]))

    low_ok = all(((m >> PIN["nRESET"]) & 1) == 0 for m in mid)
    print("   nRESET reads 0 while held: %s" % ("YES" if low_ok else "NO"))

    # Release to HIGH-Z (stop driving entirely) and see if something pulls it up.
    # If the line rises with the probe NOT driving, an external pull-up exists
    # => the pin is genuinely connected to the target board.
    d.pins(0, 0)
    time.sleep(0.05)
    rel = d.pins()
    high = (rel >> PIN["nRESET"]) & 1
    print("released to HIGH-Z   : 0x%02X  nRESET=%d" % (rel, high))
    if low_ok and high == 1:
        print("   => line is driven LOW by us and pulled HIGH by the target:")
        print("      a real external pull-up exists. nRESET IS CONNECTED.")
    elif low_ok and high == 0:
        print("   => goes low, but stays low in high-Z: NO pull-up seen.")
        print("      Pin may be floating/unconnected on the target side.")
    else:
        print("   => INCONCLUSIVE: could not confirm the drive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
