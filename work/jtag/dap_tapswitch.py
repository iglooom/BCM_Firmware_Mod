#!/usr/bin/env python3
"""Does the OnCE aux-TAP selection PERSIST across TLR and across processes?

Symptom: dap_validate.py T1 read 0x07C1C01D (the OnCE value) where the JTAGC
IDCODE 0x4AE43041 was expected - in a FRESH PROCESS, immediately after
TMS_RESET.  If true, the aux TAP survives Test-Logic-Reset, which would mean:

  * my earlier "reset_tap()" never returned control to the JTAGC,
  * every dap_once.py reading after the first select was taken with the OnCE
    TAP still active, and
  * OpenOCD's ability to read the JTAGC IDCODE is explained by the very thing
    that broke its OnCE transaction: it ENTERS DR-PAUSE, and AN4365 says
    "the JTAGC regains control of the TAP during the UPDATE-DR state IF THE
    PAUSE-DR STATE WAS ENTERED."

That would make DR-PAUSE not a bug but the DOCUMENTED way back to the master
TAP - so the correct protocol is: avoid PAUSE *within* an OnCE transaction, and
use PAUSE deliberately to return to the JTAGC.

This script tests that directly, with an explicit PAUSE-DR return path.
Read-only.
"""
import sys

sys.path.insert(0, "/home/gl/Projects/ford/BCM/Research/work/jtag")
from dap_once import Dap                                    # noqa: E402

JTAGC_ID = 0x4AE43041
ONCE_VAL = 0x07C1C01D

# EXIT1-DR -> PAUSE-DR -> EXIT2-DR -> UPDATE-DR -> RUN-TEST/IDLE
TMS_EXIT_VIA_PAUSE = [0, 1, 1, 0]


def main():
    d = Dap()
    d.connect_jtag()
    d.set_clock(1_000_000)

    print("== 1. state on entry to a FRESH process ==")
    d.reset_tap()
    v = d.dr(32, 0)
    print("   after TLR, DR(32) = 0x%08X" % v)
    if v == JTAGC_ID:
        print("   -> JTAGC selected (clean state)")
    elif v == ONCE_VAL:
        print("   -> *** OnCE STILL SELECTED *** across TLR *and* across")
        print("      process restarts.  The aux TAP latch is sticky.")
    else:
        print("   -> unexpected value")

    print("\n== 2. return to JTAGC via DR-PAUSE (AN4365 1.3.2) ==")
    # enter SHIFT-DR, shift a bit, then exit through PAUSE-DR
    d.tms([1, 0, 0])                      # RTI -> SELECT-DR -> CAPTURE-DR -> SHIFT-DR
    d.jtag_sequence([(1, [0], False)])    # -> EXIT1-DR
    d.tms(TMS_EXIT_VIA_PAUSE)             # -> PAUSE -> EXIT2 -> UPDATE -> RTI
    v = d.dr(32, 0)
    print("   after PAUSE-DR round trip, DR(32) = 0x%08X" % v)
    back = (v == JTAGC_ID)
    print("   -> %s" % ("JTAGC RECOVERED - PAUSE-DR is the way back"
                        if back else "still not JTAGC"))

    print("\n== 3. full cycle: JTAGC -> OnCE -> back -> OnCE ==")
    if back:
        d.reset_tap()
        a = d.dr(32, 0)
        d.ir(5, 0x11)                     # select OnCE
        b = d.dr(32, 0)
        d.tms([1, 0, 0])
        d.jtag_sequence([(1, [0], False)])
        d.tms(TMS_EXIT_VIA_PAUSE)         # back to JTAGC
        c = d.dr(32, 0)
        d.ir(5, 0x11)
        e = d.dr(32, 0)
        print("   JTAGC      = 0x%08X  %s" % (a, "ok" if a == JTAGC_ID else "??"))
        print("   after sel  = 0x%08X  %s" % (b, "ok" if b == ONCE_VAL else "??"))
        print("   after PAUSE= 0x%08X  %s" % (c, "ok" if c == JTAGC_ID else "??"))
        print("   re-select  = 0x%08X  %s" % (e, "ok" if e == ONCE_VAL else "??"))
        if a == JTAGC_ID and b == ONCE_VAL and c == JTAGC_ID and e == ONCE_VAL:
            print("\n   *** DETERMINISTIC TAP SWITCHING ACHIEVED ***")
            print("   We can now enter the OnCE TAP, do work, and return.")

    d.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
