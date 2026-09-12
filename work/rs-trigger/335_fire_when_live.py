#!/usr/bin/env python3
"""335 -- fire depth 4 WHILE FUN_000AD97C IS DEMONSTRABLY RUNNING.

WHY THIS EXISTS
Sec.8.4 fired depth 4 on an IDLE car, read back flag=0 / counter=0 / bit27=0,
and concluded "FUN_000AD97C is never called".  The --falsify capture during a
real fob start REFUTES that: the counter advances +10 per firmware tick and
wraps at exactly 200, the flag at 0x400095E1 reaches 1 on its own, and bit 27
goes high in 7 windows.  The function runs fine -- it is simply DORMANT when
the module is idle, which is the only state depth 4 was ever tested in.

So depth 4 was never given a fair test.  This script gives it one:

  1. POSITIVE CONTROL FIRST: poll the counter and require it to MOVE.  A
     moving counter is direct proof the target function is executing right
     now.  If it never moves we report INCONCLUSIVE and fire nothing --
     an idle car cannot answer this question (rule 27), and firing anyway
     would just reproduce Sec.8.4's null.
  2. Fire depth 4 (DID 0xDE38) at that moment.
  3. Watch bit 27 and the flag for a few seconds afterwards.

BASELINE DISCIPLINE (rule 52): the sub-state cell is permanently 1, so a
readback of 1 proves nothing.  The observable here is BIT 27, which is
independent of what we write -- we never touch it; only the firmware sets it.
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

GATE = 0x40009680       # bit 27 = 0x08000000
COUNTER_W = 0x40009670  # counter byte lives at bits 8..15
FLAG_W = 0x400095E0     # flag byte lives at bits 16..23
SUBSTATE = 0x4000967C
MAGIC_D4 = 0xDE38


def counter(p):
    return (p.read32(COUNTER_W) >> 8) & 0xFF


def flag(p):
    return (p.read32(FLAG_W) >> 16) & 0xFF


def bit27(p):
    return (p.read32(GATE) >> 27) & 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm-secs", type=float, default=25.0,
                    help="how long to wait for the counter to start moving")
    ap.add_argument("--watch-secs", type=float, default=6.0)
    ap.add_argument("--dry", action="store_true",
                    help="control only: prove liveness, fire NOTHING")
    a = ap.parse_args()

    with Peeker() as p:
        p.wake()

        print("=" * 70)
        print("STEP 1 -- POSITIVE CONTROL: is FUN_000AD97C executing?")
        print("  Waiting up to %.0f s for the counter to MOVE." % a.arm_secs)
        print("  Press the fob (LOCK, then RemoteStart) to wake the path.")
        print("=" * 70)

        t0 = time.time()
        seen = []
        base = counter(p)
        moved = False
        while time.time() - t0 < a.arm_secs:
            c = counter(p)
            if c != base:
                seen.append((time.time() - t0, base, c))
                base = c
                if len(seen) >= 3:
                    moved = True
                    break
            time.sleep(0.01)

        for t, o, n in seen[:6]:
            print("   t=%6.3f  counter %3d -> %3d" % (t, o, n))

        if not moved:
            print("\n  CONTROL FAILED -- the counter never moved.")
            print("  The target function is dormant, so this run cannot say")
            print("  anything about depth 4.  INCONCLUSIVE, not a negative.")
            print("  Re-run and press the fob while it is waiting.")
            return 2

        print("\n  CONTROL PASSED -- counter is advancing, the function IS")
        print("  running right now.  This is the state Sec.8.4 never tested.")

        pre = {"bit27": bit27(p), "flag": flag(p),
               "sub": (p.read32(SUBSTATE) >> 26) & 3, "cnt": counter(p)}
        print("\n  pre-fire baseline: bit27=%d flag=0x%02X sub=%d counter=%d"
              % (pre["bit27"], pre["flag"], pre["sub"], pre["cnt"]))

        if a.dry:
            print("\n  --dry: firing nothing.  Control-only run complete.")
            return 0

        print("\n" + "=" * 70)
        print("STEP 2 -- FIRE DEPTH 4 (0x%04X) NOW" % MAGIC_D4)
        print("=" * 70)
        ok, val = read_did(p, MAGIC_D4)
        print("  response: %s" % (bytes(val).hex().upper() if ok else val))

        print("\n" + "=" * 70)
        print("STEP 3 -- WATCH bit 27 (we never write it; only firmware does)")
        print("=" * 70)
        t0 = time.time()
        hi = 0
        prev = None
        while time.time() - t0 < a.watch_secs:
            b, f, c = bit27(p), flag(p), counter(p)
            cur = (b, f)
            if cur != prev:
                print("   t=%6.3f  bit27=%d  flag=0x%02X  counter=%3d"
                      % (time.time() - t0, b, f, c))
                prev = cur
            if b:
                hi += 1
            time.sleep(0.01)

        print("\n" + "=" * 70)
        print("  bit27 observed HIGH in %d samples after the trigger" % hi)
        if hi:
            print("  => DEPTH 4 WORKS when fired while the path is live.")
        else:
            print("  => bit 27 never rose.  Depth 4 does not drive it even")
            print("     with the function demonstrably running.")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
