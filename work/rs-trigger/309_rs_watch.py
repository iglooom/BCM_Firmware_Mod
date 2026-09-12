#!/usr/bin/env python3
"""Watch the remote-start state cells while the OPERATOR performs a REAL
remote start with the fob (LOCK, then RemoteStart x2).

This is the ground truth the whole investigation has lacked: every negative so
far (7 bench conditions + 2 vehicle depths) says "the guard refuses", and none
of them shows what the guard looks like when it ACCEPTS.

WHAT IT DOES
  Polls a small set of cells as fast as the peek service allows and records
  every CHANGE with a timestamp, so a transient is visible.  It prints a live
  running line so the operator can see it is alive while pressing.

⚠ SAMPLING BLINDNESS (AGENTS.md rule 40) -- stated up front, not discovered
  later.  Round-robin peek over N cells runs at roughly 13/N Hz.  With 5 cells
  that is ~2.6 Hz per cell, i.e. ~380 ms between samples of the SAME cell.
  bench_session_4.md Sec.4.4 already caught this: 60 ms power_mode pulses were
  MISSED by the peek sampler and only the wire saw them.  So:
     * a cell that CHANGES will very likely be caught if it stays changed for
       more than ~0.4 s (a remote start lasts tens of seconds);
     * a BRIEF transient may be missed entirely, and a null here is therefore
       NOT proof the cell never moved.
  To reduce N, the default watch list is deliberately SHORT.  Use --gate to
  watch only the two gate-field candidates at maximum rate.

USAGE
    python3 309_rs_watch.py            # default set, ~60 s
    python3 309_rs_watch.py --gate     # only the gate fields, fastest
    python3 309_rs_watch.py --secs 120

Then perform the remote start.  Ctrl-C to stop early; the summary still prints.
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bench"))
from peeklib import Peeker  # noqa: E402

FULL = [
    (0x40009680, "gate_pref   (>>27)&7 must be 7"),
    (0x40001D84, "power_mode word (+1 = mode)"),
    (0x40009648, "hold timer (+0x5C)"),
    (0x40002DA0, "rke_command_code"),
]
# The ACTIVE-phase set: what does a real remote start look like once it is
# RUNNING?  vehicle_session_1.md Sec.3 is the gap -- the --gate run never
# watched power_mode, and 0x80 does not transmit while the car is locked.
ACTIVE = [
    (0x40001D84, "power_mode word (+1 = mode)"),
    (0x40009680, "gate_pref   bit27 = the blocker"),
    (0x40009648, "hold timer (+0x5C), 10ms ticks"),
]
GATE = [
    (0x40009680, "gate_pref   (>>27)&7 must be 7"),
    (0x40009668, "gate_alt"),
]
# THE FALSIFIER SET (Sec.8.4).  Idle measurement said FUN_000AD97C is never
# called, because its counter stays 0 while sub-state is already 1 -- and the
# counter increments OUTSIDE the flag test, so a running function must tick it.
# That was measured on an IDLE car.  Bit 27 provably rises during a real fob
# start, so this set asks the decisive question: during the 1.686 s window,
# does the counter move?
#   counter moves  -> the function DOES run; my Sec.8.4 claim is WRONG
#   counter pinned -> confirmed, and bit 27 is set by some OTHER writer
# 0x40009670 carries the counter byte at +0x86 (bits 8..15 of this word).
FALSIFY = [
    (0x40009680, "gate word    -- bit27 = the 1.686 s window"),
    (0x40009670, "counter word -- byte +0x86 MUST tick if AD97C runs"),
    (0x400095E0, "minutes +4 | FLAG +5 -- does the flag ever go 1?"),
]


def gate3(w):
    return (w >> 27) & 7


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secs", type=float, default=60.0)
    ap.add_argument("--gate", action="store_true",
                    help="watch only the gate fields (fastest per-cell rate)")
    ap.add_argument("--active", action="store_true",
                    help="ACTIVE-phase set: power_mode + gate + hold timer")
    ap.add_argument("--falsify", action="store_true",
                    help="Sec.8.4 falsifier: does AD97C's counter tick during "
                         "a REAL fob start?")
    a = ap.parse_args()

    cells = (FALSIFY if a.falsify else
             GATE if a.gate else (ACTIVE if a.active else FULL))
    print("=" * 72)
    print("WATCHING %d cells for %.0f s -- perform the remote start NOW"
          % (len(cells), a.secs))
    print("  (LOCK, then RemoteStart twice)")
    print("=" * 72)
    for addr, desc in cells:
        print("   0x%08X  %s" % (addr, desc))
    print()

    last = {}
    changes = []
    seen = {addr: set() for addr, _ in cells}
    t0 = time.time()
    n = 0
    with Peeker() as p:
        p.wake()
        t0 = time.time()
        try:
            while time.time() - t0 < a.secs:
                for addr, desc in cells:
                    try:
                        v = p.read32(addr)
                    except Exception:
                        v = None
                    n += 1
                    t = time.time() - t0
                    key = "ERR" if v is None else "%08X" % v
                    seen[addr].add(key)
                    if addr not in last:
                        last[addr] = key
                        print("  %7.3f  0x%08X  init %s%s"
                              % (t, addr, key,
                                 "   gate3=%d" % gate3(v) if v is not None
                                 and addr in (0x40009680, 0x40009668) else ""))
                    elif key != last[addr]:
                        extra = ""
                        if v is not None and addr in (0x40009680, 0x40009668):
                            extra = "   gate3=%d%s" % (
                                gate3(v),
                                "   *** GATE OPEN ***" if gate3(v) == 7 else "")
                        print("  %7.3f  0x%08X  %s -> %s%s"
                              % (t, addr, last[addr], key, extra))
                        changes.append((t, addr, last[addr], key))
                        last[addr] = key
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n  (stopped by operator)")

    el = time.time() - t0
    print()
    print("=" * 72)
    print("SUMMARY  -- %d samples in %.1f s (%.1f reads/s overall, %.2f Hz/cell)"
          % (n, el, n / el if el else 0, (n / el / len(cells)) if el else 0))
    print("=" * 72)
    print("  %d change event(s)" % len(changes))
    for t, addr, o, v in changes:
        print("     %7.3f  0x%08X  %s -> %s" % (t, addr, o, v))
    print()
    print("  distinct values per cell:")
    for addr, desc in cells:
        vals = sorted(seen[addr])
        print("     0x%08X  %-32s %d value(s): %s"
              % (addr, desc, len(vals), " ".join(vals[:6])))
    print()
    if not changes:
        print("  ⚠ NO CHANGES SEEN.  Per the sampling-blindness note above this")
        print("    is NOT proof nothing moved -- a sub-0.4 s transient would be")
        print("    missed.  Re-run with --gate (2 cells, ~6 Hz each) before")
        print("    treating it as a negative.")
    else:
        g = [c for c in changes if c[1] in (0x40009680, 0x40009668)]
        print("  gate-field changes: %d" % len(g))
        if any(gate3(int(v, 16)) == 7 for _, _, _, v in g if v != "ERR"):
            print("  *** THE GATE REACHED 7 -- the blocking term is satisfied")
            print("      during a real remote start.  This is the answer. ***")


if __name__ == "__main__":
    main()
