#!/usr/bin/env python3
"""Release nRESET via the REAL code path, then read it.

Bug in reset_midpulse.py: it "released" with d.pins(0, 0) - select=0 selects
NO pins, so PIN_nRESET_OUT(1) is never called and the pad keeps whatever state
the last *assert* left it in (driven LOW).  The readback of 0 was therefore a
measurement of our own stuck output, not of the line.

Correct release: select=nRESET, value=nRESET  -> PIN_nRESET_OUT(1) -> high-Z
with the pull-up enabled (PullFix firmware).

Ground truth to distinguish:
  * If, after a genuine release, nRESET reads 1  -> something holds it high.
    With our pull-up now on, that alone is not proof of a target connection,
    so we ALSO test with our pull-up defeated: assert low, release, and see
    whether the line rises FAST (external strong-ish pull) or stays low.
  * The decisive discriminator is TDO/other pins vs nRESET behaviour and,
    ultimately, doing this while the BCM is KNOWN ALIVE.
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

    print("A. idle (read only, select=0)      : 0x%02X  nRESET=%d"
          % (d.pins(), (d.pins() >> 7) & 1))

    print("\nB. ASSERT  (select=nRESET, value=0)")
    for i in range(3):
        v = d.pins(0, M_NRESET)
        print("     sample %d: 0x%02X  nRESET=%d" % (i, v, (v >> 7) & 1))

    print("\nC. RELEASE (select=nRESET, value=nRESET)  <-- the real code path")
    v = d.pins(M_NRESET, M_NRESET)
    print("     immediately : 0x%02X  nRESET=%d" % (v, (v >> 7) & 1))
    for dly in (0.01, 0.05, 0.2, 1.0):
        time.sleep(dly)
        v = d.pins()          # read-only; does not disturb the pad
        print("     after %5.2fs: 0x%02X  nRESET=%d  %s"
              % (dly, v, (v >> 7) & 1, dec(v)))

    final = (d.pins() >> 7) & 1
    print("\nverdict: nRESET after genuine release = %d" % final)
    if final == 1:
        print("   line is HIGH when not driven -> release works.")
        print("   (Our own pull-up is enabled, so this does NOT by itself")
        print("    prove a target connection - but it does prove the pad is")
        print("    no longer stuck low, which was the previous defect.)")
    else:
        print("   still LOW after a genuine release: either the target is")
        print("   holding RESET low (it is halted), or the pin is unwired.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
