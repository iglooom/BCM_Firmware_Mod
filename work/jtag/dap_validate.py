#!/usr/bin/env python3
"""Validate the TAP state machine of dap_once.py against KNOWN TRUTH.

dap_once.py produced a suspicious result: five different OnCE register selects
all returned the identical value 0x07C1C01D, the OnCE IR capture read 0x3FF
(all ones = nothing driving TDO), and a plain DR read straight after selecting
the aux TAP gave 0xFFFFFFFF where OpenOCD reads 0x07C1C01D.  Two tools
disagreeing IS the finding (rule 17) - so before reporting any register value,
prove the state machine is right using facts we already know independently:

  T1  After TLR, a 32-bit DR read must return the JTAGC IDCODE 0x4AE43041.
      (IDCODE is auto-selected at reset - no IR scan needed.)
  T2  Explicitly loading IR=0x01 (IDCODE) must give the same value.
  T3  Loading IR=0x1F (BYPASS) and shifting a pattern must return that pattern
      shifted left by exactly one bit - 0xA5A5A5A5 -> 0x4B4B4B4A.  This is the
      single most sensitive test of shift alignment: a one-cycle error anywhere
      changes the answer.
  T4  The IR capture value itself.  IEEE 1149.1 requires the IR to capture
      0bxxx01 in CAPTURE-IR, so the low two bits of any IR read must be 0b01.
      An all-ones capture means we are not actually in SHIFT-IR.

Only if T1-T4 all pass is the driver trustworthy enough to interpret an aux-TAP
register.  Read-only throughout.
"""
import sys

sys.path.insert(0, "/home/gl/Projects/ford/BCM/Research/work/jtag")
from dap_once import Dap, TMS_RESET, TMS_RTI, TMS_RTI_TO_SHIFTIR, \
    TMS_RTI_TO_SHIFTDR, TMS_EXIT_TO_RTI            # noqa: E402

fails = []


def check(name, ok, detail=""):
    print("   [%s] %-42s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        fails.append(name)


def main():
    d = Dap()
    d.connect_jtag()
    d.set_clock(1_000_000)
    print("== state-machine validation ==\n")

    # T1 - IDCODE after reset, no IR scan
    d.reset_tap()
    v = d.dr(32, 0)
    check("T1 IDCODE after TLR (no IR)", v == 0x4AE43041, "0x%08X" % v)

    # T2 - explicit IDCODE opcode
    d.reset_tap()
    ir_cap = d.ir(5, 0x01)
    v = d.dr(32, 0)
    check("T2 IDCODE via IR=0x01", v == 0x4AE43041, "0x%08X" % v)

    # T4 - IR capture must end in 0b01 per IEEE 1149.1
    check("T4 IR capture low bits == 0b01", (ir_cap & 3) == 1,
          "captured 0x%02X (low2=%s)" % (ir_cap, format(ir_cap & 3, "02b")))

    # T3 - BYPASS shift alignment, the sharpest test
    d.reset_tap()
    d.ir(5, 0x1F)
    v = d.dr(32, 0xA5A5A5A5)
    check("T3 BYPASS shift == input<<1", v == 0x4B4B4B4A,
          "got 0x%08X, expected 0x4B4B4B4A" % v)

    print("\n== verdict ==")
    if fails:
        print("   DRIVER IS NOT TRUSTWORTHY - %d check(s) failed: %s"
              % (len(fails), ", ".join(fails)))
        print("   Any OnCE register value read with it is meaningless.")
    else:
        print("   All state-machine checks pass. The driver shifts correctly,")
        print("   so an aux-TAP disagreement with OpenOCD is a real protocol")
        print("   difference, not a bit-alignment bug.")

    d.disconnect()
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
