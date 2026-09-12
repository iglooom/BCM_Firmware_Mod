#!/usr/bin/env python3
"""Is Path A UPSTREAM of the lock command, or a consequence of it?

`278_patha_rke_test.py` established (controlled, idle-matched) that an RKE press
raises `APP_lock_request_input` and `APP_req_word_74` bits 9|10, and that a
matched idle window produces zero.  That settles WHETHER, not WHICH WAY.

  H_UP   : RKE -> lock_request_input -> edge detector -> lock_command.
           Prediction: lock_request_input rises BEFORE lock_command, by a
           STABLE offset that survives a change in press cadence.
  H_DOWN : the lock command (or a common parent) is what raises the input.
           Prediction: the input rises at or after the command.
  H_PHASE: the offset is a cadence artifact.
           Prediction: it MOVES when --gap changes.

⚠ THE FALSIFIER IS THE GAP SWEEP, AND IT IS NOT OPTIONAL (AGENTS.md rule 26).
Two signals locked to the same press cadence show a CONSTANT offset at any
arbitrary phase.  bench_session_2.md §6.1 published "+1040 ms, twice" from
exactly that and had to withdraw it.  So every condition here is run at TWO
inter-press gaps, and an offset is reported as causal ONLY if it survives both.
Pairing is nearest-neighbour, never next-rising-edge (§6.2).

⚠⚠ THE GAP SWEEP IS NOT SUFFICIENT, AND THIS SCRIPT LEARNED THAT THE HARD WAY.
Its first version paired `lock_request_input` rises against `lock_command -> 01`
ONLY, and reported "H_DOWN survives: -0.479 s @gap 1.2, -0.517 s @gap 0.7,
drift 39 ms".  The gap sweep passed and the conclusion was still wrong.

Cause: one RKE lock press emits a fixed-shape BURST -- the triplet
LOCK, LOCK (+0.51 s), UNLOCK (+0.52 s) of bench_session_1.md §5.3 -- whose
INTERNAL spacing is invariant to the inter-press gap.  Varying --gap therefore
cannot falsify a pairing to the wrong MEMBER of the burst; the 0.51 s "lag" was
just the triplet's own spacing.  Paired against `-> 02` instead, 4 of 5 rises
land at +0.010 s, i.e. simultaneous at the round-robin floor.

⇒ Rule: when the stimulus produces a multi-event burst, pair against EVERY
  destination value and report which one wins, rather than choosing one a
  priori.  A stable offset to the wrong partner is indistinguishable from a lag.
  This script now does that automatically.

Also note the ±10 ms floor: with N cells polled round-robin, two cells cannot be
ordered more finely than one round-robin period.  The script prints that period
and refuses to call anything below it an ordering.
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from peeklib import Peeker, PeekError          # noqa: E402

LOGS = os.path.join(HERE, "logs")

W_LOCKREQ = 0x40008D2C
W_LOCKCMD = 0x40002E70
CELLS = [W_LOCKREQ, W_LOCKCMD]


def run(p, gap, presses, hold):
    log = os.path.join(LOGS, "%s_order_stim.log" % time.strftime("%Y%m%dT%H%M%S"))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "rfa_sim.py"), "press",
         "--cmd", "lock", "--n", str(presses), "--hold", str(hold),
         "--gap", str(gap), "--settle", "1.0"],
        stdout=open(log, "w"), stderr=subprocess.STDOUT)
    t0 = time.time()
    last, trace = {}, []
    n = 0
    while proc.poll() is None:
        for c in CELLS:
            try:
                v = p.read32(c)
            except PeekError:
                continue
            n += 1
            t = time.time() - t0
            if c not in last:
                last[c] = v
                continue
            if v != last[c]:
                trace.append((t, c, v))
                last[c] = v
    dur = time.time() - t0
    return trace, n, dur, log


def rises(trace, cell, byte_val):
    return [t for t, c, v in trace
            if c == cell and (v >> 24) & 0xFF == byte_val]


def nearest(ea, eb, window=1.0):
    """Nearest-neighbour pairing (rule 26).  Returns signed offsets b - a."""
    out = []
    for ta in ea:
        best = None
        for tb in eb:
            d = tb - ta
            if abs(d) <= window and (best is None or abs(d) < abs(best)):
                best = d
        if best is not None:
            out.append(best)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--presses", type=int, default=8)
    ap.add_argument("--hold", type=float, default=0.30)
    ap.add_argument("--gaps", default="1.2,0.7")
    a = ap.parse_args()
    gaps = [float(g) for g in a.gaps.split(",")]

    out = {}
    with Peeker() as p:
        p.assert_live()
        for g in gaps:
            print("\n=== gap %.2f s ===" % g)
            trace, n, dur, log = run(p, g, a.presses, a.hold)
            period = len(CELLS) * dur / max(n, 1)
            req = rises(trace, W_LOCKREQ, 0x01)
            print("  %.1f Hz/cell, round-robin period %.1f ms  <-- ordering floor"
                  % (n / dur / len(CELLS), 1000 * period))
            print("  lock_request_input rises: %d" % len(req))

            # Pair against EVERY destination value, not one chosen a priori.
            # The burst has internal structure the gap sweep cannot falsify.
            byval = {}
            for val in (0x01, 0x02):
                cmd = rises(trace, W_LOCKCMD, val)
                offs = nearest(req, cmd)
                if not offs:
                    print("    vs lock_command->%02X: %d edges, no pairs"
                          % (val, len(cmd)))
                    continue
                mean = sum(offs) / len(offs)
                spread = max(offs) - min(offs)
                byval[val] = dict(n=len(offs), mean=mean, spread=spread,
                                  offsets=offs, n_edges=len(cmd))
                print("    vs lock_command->%02X: n=%d mean %+.3f s spread %.3f s"
                      % (val, len(offs), mean, spread))
                print("       %s" % ["%+.3f" % o for o in offs])

            # The winning partner is the one with the SMALLEST |mean|: a cell
            # pairs with the event it actually coincides with.
            best = min(byval, key=lambda v: abs(byval[v]["mean"])) if byval else None
            if best is not None:
                print("    => nearest partner is lock_command->%02X at %+.3f s"
                      % (best, byval[best]["mean"]))
            mean = byval[best]["mean"] if best is not None else None
            out[g] = dict(rate=n / dur / len(CELLS), period=period,
                          n_req=len(req), byval={hex(k): v
                                                 for k, v in byval.items()},
                          best_partner=(hex(best) if best is not None else None),
                          mean=mean, stim_log=log)
            time.sleep(2.0)

    print("\n" + "=" * 68)
    print("FALSIFICATION TEST (rule 26): does the offset survive a gap change?")
    means = {g: out[g]["mean"] for g in gaps if out[g]["mean"] is not None}
    floor = max(out[g]["period"] for g in gaps)
    for g, m in means.items():
        print("  gap %.2f s -> mean offset %+.3f s" % (g, m))
    print("  ordering floor (round-robin period): %.0f ms" % (1000 * floor))

    if len(means) < 2:
        print("\n  => INCONCLUSIVE: need a paired result at two gaps.")
    else:
        vals = list(means.values())
        drift = max(vals) - min(vals)
        print("  offset drift across gaps: %.3f s" % drift)
        if drift > 0.25:
            print("\n  => H_PHASE: the offset MOVED with the cadence. It is a")
            print("     phase artifact, not a lag. No ordering is established.")
        elif all(abs(v) < floor for v in vals):
            print("\n  => SIMULTANEOUS at the limit of this instrument: the two")
            print("     cells move within one round-robin period. They are ONE")
            print("     event, not two pipeline stages. No ordering claimable.")
        elif all(v > floor for v in vals):
            print("\n  => H_UP SURVIVES: lock_request_input rises BEFORE")
            print("     lock_command by a stable %.0f ms at BOTH cadences."
                  % (1000 * sum(vals) / len(vals)))
            print("     Path A is upstream of the lock command on this stimulus.")
        elif all(v < -floor for v in vals):
            print("\n  => H_DOWN SURVIVES: lock_command precedes the input;")
            print("     Path A's input is a consequence, not a cause.")
        else:
            print("\n  => MIXED/INCONCLUSIVE: signs disagree across gaps.")
    print("=" * 68)

    path = os.path.join(LOGS, "%s_order.json" % time.strftime("%Y%m%dT%H%M%S"))
    with open(path, "w") as fh:
        json.dump({str(k): v for k, v in out.items()}, fh, indent=2)
    print("\nwrote %s" % path)


if __name__ == "__main__":
    main()
