#!/usr/bin/env python3
"""338 -- measure how long an injected enum 8 actually SURVIVES.

WHY: 336 and 337 both reported our 0x1808 "gone after 140 ms".  That number is
identical to the millisecond across two runs because it is the SAMPLER's loop
period (5 cells x ~25 ms UDS round trip + 20 ms sleep), not a property of the
firmware -- AGENTS.md rule 26, a suspiciously round repeated delta is a shared
cadence until proven otherwise.  The true lifetime is somewhere in (0, 140] ms.

This matters for the design: if the cell is cleared within one 10 ms tick, no
one-shot DID can ever win, and the fix must be a firmware cave that re-asserts
the value on a periodic path.  If it survives a few hundred ms, a tighter
injection may still work without reflashing.

METHOD: poll ONE cell only, as fast as the transport allows, so the loop period
is a single round trip (~25 ms) instead of five.  Fire, then sample.

POSITIVE CONTROL (rule 27): we first prove the write is OBSERVABLE at all by
requiring at least one sample to show enum 8.  If none does, the run is
INCONCLUSIVE -- it would mean our sampler is slower than the lifetime and we
have measured nothing.

NOTE the observable is independent of the sampler's blindness in one direction
only: seeing enum 8 in N consecutive samples is a LOWER bound on lifetime.
Never seeing it is NOT proof the write failed (it may have been erased between
samples) -- hence the explicit INCONCLUSIVE arm.

SAFETY: writes a remote-start command code.  PARK, brake set, open air.
"""
import sys
import os
import time
import argparse
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "work", "bench"))

from peeklib import Peeker  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "did", os.path.join(ROOT, "work", "bench", "293_did_read.py"))
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
read_did = _m.read_did

RKE_CODE = 0x40002DA0
DID_D2 = 0xDE16


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=40)
    ap.add_argument("--repeats", type=int, default=3,
                    help="independent fire+measure trials")
    a = ap.parse_args()

    with Peeker() as p:
        p.wake()

        print("=" * 70)
        print("CALIBRATION -- how fast can we sample ONE cell?")
        print("=" * 70)
        t0 = time.time()
        for _ in range(10):
            p.read32(RKE_CODE)
        per = (time.time() - t0) / 10.0
        print("  single-cell period = %.1f ms  (this bounds our resolution)"
              % (per * 1000.0))

        all_life = []
        for trial in range(1, a.repeats + 1):
            print("\n" + "=" * 70)
            print("TRIAL %d -- fire depth 2, then poll one cell" % trial)
            print("=" * 70)

            pre = p.read32(RKE_CODE)
            ok, val = read_did(p, DID_D2)
            t_fire = time.time()
            print("  pre=%08X  response=%s"
                  % (pre, bytes(val).hex().upper() if ok else val))

            seen8 = 0
            last8_t = None
            rows = []
            for i in range(a.samples):
                v = p.read32(RKE_CODE)
                dt = time.time() - t_fire
                rows.append((dt, v))
                if (v & 0xF) == 8:
                    seen8 += 1
                    last8_t = dt

            for dt, v in rows[:8]:
                print("   t=%6.3f  %08X  enum %d" % (dt, v, v & 0xF))
            if len(rows) > 8:
                print("   ... %d more samples" % (len(rows) - 8))

            if seen8 == 0:
                print("  INCONCLUSIVE -- enum 8 never observed.  The write may")
                print("  have been erased faster than %.0f ms." % (per * 1000))
            else:
                all_life.append(last8_t)
                print("  enum 8 seen in %d samples; last at t=%.3f s"
                      % (seen8, last8_t))
            time.sleep(0.5)

        print("\n" + "=" * 70)
        if all_life:
            print("  LOWER BOUND on lifetime: %.0f ms (max across %d trials)"
                  % (max(all_life) * 1000.0, len(all_life)))
            print("  resolution was %.0f ms per sample" % (per * 1000.0))
            if max(all_life) < 0.1:
                print("  => cleared within ~1 firmware tick.  A one-shot DID")
                print("     CANNOT win; the fix must be a firmware cave that")
                print("     re-asserts the value on a periodic path.")
            else:
                print("  => survives long enough that tighter injection may")
                print("     still be viable without reflashing.")
        else:
            print("  ALL TRIALS INCONCLUSIVE -- cannot resolve the lifetime")
            print("  with this transport.  Treat as 'shorter than %.0f ms'."
                  % (per * 1000.0))
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
