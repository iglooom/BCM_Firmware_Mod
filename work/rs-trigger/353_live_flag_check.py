#!/usr/bin/env python3
"""353 -- LIVE falsifier of the subagents' dirty-flag explanation.

CLAIM (both children, converging): APP_rke_code_commit writes 0x40003F53 = 0xFF,
and the remote-start consumer at 0x0AEEDA calls VOL_test_and_clear_dirty(p, 2),
which tests mask (0x80 >> 2) = 0x20.  Our depth-2 debug service writes 0x01 to
that byte -- bit index 7 -- which no consumer reads.  0x01 & 0x20 == 0, so the
test-and-clear returns 0 forever and the remote-start arm is never entered.

That is a falsifiable prediction about the LIVE module, testable with peek and
no reflash: right now, after our depth-2 writes, the byte should read 0x01 and
NOT have 0x20 set.

Controls:
  - read the whole word so the byte extraction is visible, not asserted
  - the word 0x40003F50 is read twice with a delay: a cell that changes under
    us would invalidate a single-sample claim
"""
import sys
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "work", "bench"))

from peeklib import Peeker  # noqa: E402

WORD = 0x40003F50
FLAG = 0x40003F53


def main():
    with Peeker() as p:
        p.wake()
        print("=" * 70)
        print("LIVE FALSIFIER -- the flag byte the RS consumer actually tests")
        print("=" * 70)
        print("  claim: real path writes 0xFF; our debug service wrote 0x01;")
        print("         RS consumer tests mask 0x20 (Volcano n=2, MSB-first)")
        print("         0x01 & 0x20 == 0  =>  can never fire")
        print()

        samples = []
        for i in range(3):
            w = p.read32(WORD)
            samples.append(w)
            print("   sample %d: word @0x%08X = %08X" % (i + 1, WORD, w))
            time.sleep(0.3)

        if len(set(samples)) != 1:
            print("\n  ⚠ the word CHANGED between samples: %s"
                  % " ".join("%08X" % s for s in samples))
            print("  A single-sample claim would be unsafe.  Reporting all.")

        w = samples[-1]
        print("\n  byte breakdown of 0x%08X (big-endian):" % WORD)
        for i in range(4):
            b = (w >> (8 * (3 - i))) & 0xFF
            mark = "   <-- 0x%08X, the flag byte" % FLAG if i == 3 else ""
            print("     0x%08X = 0x%02X%s" % (WORD + i, b, mark))

        flag = w & 0xFF
        print("\n  flag byte 0x%08X = 0x%02X" % (FLAG, flag))
        print("  remote-start consumer mask (n=2) = 0x20")
        print("  0x%02X & 0x20 = 0x%02X" % (flag, flag & 0x20))
        print()
        if (flag & 0x20) == 0:
            print("  => PREDICTION CONFIRMED on the live vehicle.")
            print("     The bit the remote-start consumer tests is CLEAR.")
            print("     Depth 2 writes a value no consumer reads, which is")
            print("     exactly why the code persists and nothing fires.")
        else:
            print("  => PREDICTION REFUTED: mask bit 0x20 IS set, so the")
            print("     'nobody reads our flag' explanation does not hold.")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
