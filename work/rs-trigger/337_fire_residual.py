#!/usr/bin/env python3
"""337 -- fire enum 8 in the RESIDUAL fob window (after release, before bit 27 drops).

WHY 336 FAILED (Sec.9):
336 asked the operator to HOLD a fob button so bit 27 (receiver active) would
be high, then injected enum 8.  Our 0x1808 landed -- and was overwritten 140 ms
later by the fob's own LOCK codes (0x1D31/0x1D51/0x1D91, low nibble 1), which
kept arriving at ~7 Hz for the whole watch.  The experiment was self-defeating:
the very transmission that opens bit 27 also floods APP_rke_command_code.

THE OPENING:
In the --falsify capture, bit 27 stayed high for 0.2-1.0 s in windows that
outlast the press.  So after RELEASE there should be a brief interval where
the receiver flag is still set but no new codes are arriving -- exactly when
our write can survive to the next read.

METHOD:
  1. Wait for bit 27 high            (fob held -- receiver live)
  2. Wait for the code cell to GO QUIET while bit 27 is STILL high
     (i.e. released, but the flag has not decayed yet)
  3. Fire depth 2 immediately, inside that residual window
  4. Watch the RUN TIMERS, not power_mode

OBSERVABLE (rule 52 -- independent of what we write):
power_mode is a useless observable here: Sec.3 proved it is constant 0x04 on
this vehicle through an entire genuine remote start.  The run timers at
base+0x34 / +0x6C advance only while the engine is actually running (Sec.5.1),
so they are the honest success signal.  We never write them.

POSITIVE CONTROL (rule 27): if bit 27 never opens, or never goes quiet while
still high, we report INCONCLUSIVE and fire nothing.

SAFETY: this synthesises a remote-start command.  PARK, brake set, open air.
No abort DID exists.
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

GATE = 0x40009680
RKE_CODE = 0x40002DA0
RUN_T1 = 0x40009620     # base+0x34 -- ticks only while running (Sec.5.1)
RUN_T2 = 0x40009658     # base+0x6C
POWER_MODE = 0x40001D84
DID_D2 = 0xDE16


def bit27(p):
    return (p.read32(GATE) >> 27) & 1


def snap(p):
    return {"gate": p.read32(GATE), "rke": p.read32(RKE_CODE),
            "t1": p.read32(RUN_T1), "t2": p.read32(RUN_T2),
            "pm": (p.read32(POWER_MODE) >> 16) & 0xFF}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm-secs", type=float, default=30.0)
    ap.add_argument("--quiet-ms", type=float, default=60.0,
                    help="code cell must be unchanged this long before firing")
    ap.add_argument("--watch-secs", type=float, default=12.0)
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args()

    with Peeker() as p:
        p.wake()
        base = snap(p)
        print("=" * 72)
        print("STEP 1 -- PRESS AND HOLD a fob button (LOCK is fine), then")
        print("          RELEASE it when told.  Waiting up to %.0f s."
              % a.arm_secs)
        print("=" * 72)
        print("  baseline  rke=%08X  t1=%08X  t2=%08X  pm=0x%02X"
              % (base["rke"], base["t1"], base["t2"], base["pm"]))

        t0 = time.time()
        while time.time() - t0 < a.arm_secs and not bit27(p):
            time.sleep(0.005)
        if not bit27(p):
            print("\n  CONTROL FAILED -- bit 27 never opened. INCONCLUSIVE.")
            return 2
        print("\n  bit 27 OPEN at t=%.3f -- receiver live." % (time.time() - t0))
        print("  >>> NOW RELEASE THE BUTTON <<<")

        # Step 2: wait for the code cell to stop changing while bit27 still 1.
        last = p.read32(RKE_CODE)
        quiet_since = time.time()
        fired_at = None
        t1 = time.time()
        while time.time() - t1 < a.arm_secs:
            b = bit27(p)
            v = p.read32(RKE_CODE)
            if v != last:
                last = v
                quiet_since = time.time()
            if not b:
                print("  bit 27 dropped before the cell went quiet -- retry.")
                return 2
            if (time.time() - quiet_since) * 1000.0 >= a.quiet_ms:
                fired_at = time.time()
                break
            time.sleep(0.004)

        if fired_at is None:
            print("\n  CONTROL FAILED -- never found a quiet interval while")
            print("  bit 27 was high.  INCONCLUSIVE, not a negative.")
            return 2

        print("\n  RESIDUAL WINDOW FOUND: code quiet %.0f ms, bit27 still 1,"
              % a.quiet_ms)
        print("  last code seen = %08X" % last)

        if a.dry:
            print("\n  --dry: firing nothing.")
            return 0

        print("\n" + "=" * 72)
        print("STEP 3 -- FIRE DEPTH 2 (0x%04X) IN THE RESIDUAL WINDOW"
              % DID_D2)
        print("=" * 72)
        ok, val = read_did(p, DID_D2)
        print("  response: %s   bit27 now = %d"
              % (bytes(val).hex().upper() if ok else val, bit27(p)))

        print("\n" + "=" * 72)
        print("STEP 4 -- WATCH THE RUN TIMERS (%.0f s)" % a.watch_secs)
        print("  these advance ONLY while the engine runs; we never write them")
        print("=" * 72)
        t0 = time.time()
        prev = None
        survived = 0
        while time.time() - t0 < a.watch_secs:
            s = snap(p)
            if (s["rke"] & 0xF) == 8:
                survived += 1
            key = (s["rke"], s["t1"], s["t2"], s["pm"])
            if key != prev:
                print("   t=%6.3f  rke=%08X(enum %d)  t1=%08X  t2=%08X  pm=0x%02X"
                      % (time.time() - t0, s["rke"], s["rke"] & 0xF,
                         s["t1"], s["t2"], s["pm"]))
                prev = key
            time.sleep(0.02)

        end = snap(p)
        print("\n" + "=" * 72)
        print("  our enum 8 was resident in %d samples" % survived)
        print("  run timer t1: %08X -> %08X   %s"
              % (base["t1"], end["t1"],
                 "MOVED" if end["t1"] != base["t1"] else "unchanged"))
        print("  run timer t2: %08X -> %08X   %s"
              % (base["t2"], end["t2"],
                 "MOVED" if end["t2"] != base["t2"] else "unchanged"))
        if end["t1"] != base["t1"] or end["t2"] != base["t2"]:
            print("  => RUN TIMERS ADVANCED -- check the vehicle.")
        else:
            print("  => no run-timer movement: no start from this attempt.")
        print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
