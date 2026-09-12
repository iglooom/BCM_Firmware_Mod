#!/usr/bin/env python3
"""336 -- fire a trigger INSIDE the fob-reception window.

THE USER OBSERVATION THAT CAUSED THIS (Sec.1, 2026-09-13):
  "if I hold any button on RKE even when not locked and ignition on, your
   scripts says gate3=7 GATE OPEN.  So it reacts on every button on keyfob
   in any mode."

That kills the idea that bit 27 is a remote-start gate.  Bits 28/29 are always
set, so (word>>27)&7 == 7 reduces to bit 27 alone, and bit 27 is simply
"a valid fob transmission is being received RIGHT NOW" -- a receiver-active
flag.  Forging it proves nothing, which is why depth 4 was the wrong idea.

What actually distinguishes remote start from lock/unlock is the COMMAND CODE:
FUN_000ADADA tests (code & 0xF) == 8.  The firmware normally sees both halves
at once -- receiver active AND enum 8 in the code cell.

So: let the FOB supply the half we cannot forge (hold any button -> bit 27),
and inject the half we can (depth 2 writes enum 8) inside that window.
No reflash needed; depth 2 is already on the flashed image.

POSITIVE CONTROL (rule 27): we refuse to fire unless bit 27 is actually
observed high.  If the fob is not transmitting, the run reports INCONCLUSIVE
rather than manufacturing a negative.

BASELINE (rule 52): every watched cell is sampled BEFORE the trigger, and the
reported observable -- did the engine-start path advance -- is independent of
the cells we write.

SAFETY: depth 2 synthesises a remote-start command.  PARK, parking brake set,
open air, bonnet clear.  There is no abort DID.
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

GATE = 0x40009680        # bit 27 = fob receiver active
COUNTER_W = 0x40009670   # counter byte at bits 8..15
RKE_CODE = 0x40002DA0    # command code word
POWER_MODE = 0x40001D84  # byte +1 = APP_power_mode
FLAG_W = 0x400095E0      # flag byte at bits 16..23

DEPTH_DID = {2: 0xDE16, 4: 0xDE38}


def snap(p):
    return {
        "gate": p.read32(GATE),
        "cnt": (p.read32(COUNTER_W) >> 8) & 0xFF,
        "rke": p.read32(RKE_CODE),
        "pm": (p.read32(POWER_MODE) >> 16) & 0xFF,
        "flag": (p.read32(FLAG_W) >> 16) & 0xFF,
    }


def show(tag, s):
    print("  %-14s gate=%08X bit27=%d  counter=%3d  rke=%08X  "
          "power_mode=0x%02X  flag=0x%02X"
          % (tag, s["gate"], (s["gate"] >> 27) & 1, s["cnt"], s["rke"],
             s["pm"], s["flag"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--depth", type=int, default=2, choices=sorted(DEPTH_DID))
    ap.add_argument("--arm-secs", type=float, default=30.0)
    ap.add_argument("--watch-secs", type=float, default=10.0)
    ap.add_argument("--dry", action="store_true",
                    help="control only -- prove the window, fire NOTHING")
    a = ap.parse_args()

    with Peeker() as p:
        p.wake()

        print("=" * 72)
        print("STEP 1 -- WAIT FOR THE FOB WINDOW  (bit 27 high)")
        print("  HOLD ANY BUTTON ON THE KEYFOB now and keep holding.")
        print("  Waiting up to %.0f s." % a.arm_secs)
        print("=" * 72)

        base = snap(p)
        show("baseline", base)

        t0 = time.time()
        opened = 0.0
        while time.time() - t0 < a.arm_secs:
            if (p.read32(GATE) >> 27) & 1:
                opened = time.time() - t0
                break
            time.sleep(0.005)

        if not opened:
            print("\n  CONTROL FAILED -- bit 27 never went high.")
            print("  The fob was not transmitting, so this run cannot say")
            print("  anything about the trigger.  INCONCLUSIVE, not negative.")
            return 2

        print("\n  CONTROL PASSED -- bit 27 high at t=%.3f s." % opened)
        print("  The receiver is live; this is the window the firmware uses.")

        if a.dry:
            print("\n  --dry: firing nothing.")
            for _ in range(5):
                show("in-window", snap(p))
                time.sleep(0.05)
            return 0

        did = DEPTH_DID[a.depth]
        print("\n" + "=" * 72)
        print("STEP 2 -- FIRE DEPTH %d (DID 0x%04X) INSIDE THE WINDOW"
              % (a.depth, did))
        print("=" * 72)
        ok, val = read_did(p, did)
        print("  response: %s" % (bytes(val).hex().upper() if ok else val))

        print("\n" + "=" * 72)
        print("STEP 3 -- WATCH  (%.0f s)" % a.watch_secs)
        print("=" * 72)
        t0 = time.time()
        prev = None
        pm_seen = set()
        while time.time() - t0 < a.watch_secs:
            s = snap(p)
            pm_seen.add(s["pm"])
            key = (s["pm"], s["rke"], (s["gate"] >> 27) & 1)
            if key != prev:
                show("t=%6.3f" % (time.time() - t0), s)
                prev = key
            time.sleep(0.02)

        print("\n" + "=" * 72)
        print("  power_mode values seen after the trigger: %s"
              % " ".join("0x%02X" % v for v in sorted(pm_seen)))
        print("  baseline power_mode was 0x%02X" % base["pm"])
        if pm_seen - {base["pm"]}:
            print("  => power_mode CHANGED -- inspect above, and check the car.")
        else:
            print("  => power_mode unchanged.  No start from this attempt.")
        print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
