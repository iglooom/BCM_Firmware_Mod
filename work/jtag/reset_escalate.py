#!/usr/bin/env python3
"""Escalating reset attempts on a core halted in OnCE debug mode.

⚠ SUPERSEDED - this script's recorded "all attempts failed" run was INVALID.
   It predates three firmware fixes and one fix in this file's own logic:
     1. DAP_SWJ_Pins indexed by GPIO number, not protocol bit -> the command
        never reached the pin (PIN_nRESET_OUT was dead code);
     2. PIN_nRESET_OUT itself never called gpio_put();
     3. RP2350 pads reset with PDE=1, so "high-Z" still pulled the line down;
     4. releasing via d.pins(M_NRESET, M_NRESET) is required - an earlier
        variant used select=0, which selects NO pins and leaves the pad
        driven low from the previous assert.
   With the PullFix firmware a 50 ms pulse recovers the module (0 -> 14/14
   UDS responses). Use work/jtag/reset_release.py for the verified sequence.
   See docs/jtag_bringup.md §6.4 and AGENTS.md rule 33.


Context: nRESET is now PROVEN wired and controllable (dap_reset_hid.py reports
wired_and_verified=True; the pin follows the drive 0x07 <-> 0x87).  A 100 ms
pulse did NOT revive the halted BCM.  This tries progressively stronger
sequences and checks CAN after each one, so we learn which - if any - clears
OnCE debug state.

Each attempt is followed by an independent CAN liveness check, so a success is
measured on the vehicle bus, not inferred from the probe.
"""
import subprocess, sys, time, glob

PIN_NTRST, PIN_NRESET = 5, 7
M_NTRST, M_NRESET = 1 << PIN_NTRST, 1 << PIN_NRESET
CANCHK = "/home/gl/Projects/ford/BCM/Research/work/bench/canchk.sh"


def node():
    for n in sorted(glob.glob("/dev/hidraw*")):
        name = n.split("/")[-1]
        try:
            u = open("/sys/class/hidraw/%s/device/uevent" % name).read().upper()
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


def alive():
    """True if the BCM answers UDS TesterPresent on can0."""
    r = subprocess.run(["bash", CANCHK], capture_output=True, text=True, timeout=120)
    out = r.stdout
    resp = 0
    for line in out.splitlines():
        if "responses" in line:
            try:
                resp = int(line.split(":")[1].strip())
            except (ValueError, IndexError):
                pass
    return resp > 0, resp


def report(label, d):
    ok, n = alive()
    print("   -> CAN: %d TesterPresent responses  %s" % (n, "*** REVIVED ***" if ok else "still halted"))
    return ok


def main():
    n = node()
    if not n:
        print("no probe")
        return 1
    d = Dap(n)
    d.connect()
    print("baseline pins: 0x%02X" % d.pins())

    ok, cnt = alive()
    print("\nstart state: %d responses (%s)" % (cnt, "ALIVE" if ok else "halted"))
    if ok:
        print("BCM is already running - nothing to recover.")
        return 0

    # ⚠ nTRST attempts REMOVED as invalid instruments.
    # PIN_nTRST_OUT in the probe firmware is a stub (`; //Not available`), so
    # every nTRST drive is a silent no-op. A "C: nTRST+nRESET" attempt would
    # have been an nRESET-only pulse wearing a misleading label - the same
    # rule-27 trap as the all-zeros pin readback. Only nRESET is real here.
    attempts = [
        ("A: nRESET low 500 ms",      lambda: (d.pins(0, M_NRESET), time.sleep(0.5), d.pins(M_NRESET, M_NRESET))),
        ("B: nRESET low 2 s",         lambda: (d.pins(0, M_NRESET), time.sleep(2.0), d.pins(M_NRESET, M_NRESET))),
        ("C: nRESET low 5 s",         lambda: (d.pins(0, M_NRESET), time.sleep(5.0), d.pins(M_NRESET, M_NRESET))),
    ]

    for label, fn in attempts:
        print("\n=== %s ===" % label)
        fn()
        time.sleep(1.5)          # let the module boot
        print("   pins now 0x%02X" % d.pins())
        if report(label, d):
            print("\nSUCCESS: %s recovered the module." % label)
            return 0

    print("\nAll attempts failed - the core stays halted.")
    print("Consistent with OnCE debug state surviving a pin reset; a power")
    print("cycle remains the only known recovery.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
