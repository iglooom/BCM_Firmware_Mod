#!/usr/bin/env python3
"""Does the RKE press drive PATH A?  A falsifiable test, not a correlation.

BACKGROUND -- the bit-numbering correction (work/owner/277_bitnum_adjudicate.py)
The bench sees `APP_req_word_74` 0x40008E74 go 0x02100000 -> 0x02100600 under an
RKE lock press.  `bench_session_2.md` §4.1 read the novel mask 0x600 as "word
bits 17 and 18" and put layer 36's withdrawn `0x8B3D6` (bit 17) lead back in
play.  That reading is WRONG, and the instructions say so without any appeal to
convention:

  APP_lock_req_edge_detect_A/B  (0x86F90 / 0x8A812) contain the LITERAL
  constants 0x400 and 0xFFFFFDFF / 0xFFFFFBFF, i.e. LSB bit 9 = level memory
  and LSB bit 10 = edge event.   0x600 = 0x200 | 0x400 = bits 9|10 EXACTLY.

  The RKE writer sites decode (sh/mb/me, wrap-aware) to LSB masks 0x00078000
  and 0x0001C000, i.e. LSB bits 14..18 -- layer 36's "bits 15..20" in MSB
  numbering.  These DO NOT INTERSECT 0x600.

⇒ The cell the bench watched move is Path A's edge detector, not the RKE
  handoff field.  Layer 36's bit-level negative is NOT refuted by that
  observation, and §4.1's revival of the bit-17 lead is withdrawn.

THE NEW QUESTION, and why it matters
`central_locking_chain.md` §1 states Path A and Path B are disjoint and that
Path A is "*not* RKE (a)".  But an RKE press demonstrably raises
`APP_lock_request_input` (0x40008D2C -> 0x01) and then bits 9|10.  Either the
disjointness claim is wrong, or something else is driving Path A and merely
coincides with our presses.

PREDICTIONS, stated before measuring
  H_RKE  : Path A is driven BY the RKE command.
           => lock_request_input rises on lock AND unlock presses,
              and NOT during a matched idle window.
  H_COINC: Path A is driven by something periodic/unrelated.
           => it rises at a similar rate during the idle window.

CONDITIONS (each the same duration, same bus activity, order randomised)
  1. lock presses
  2. unlock presses
  3. IDLE-ONLY: the RFA idle stream runs, so the bus is equally busy and the
     module equally awake, but NO command bits are ever set.

Condition 3 is the control the whole test rests on: without it, "it moved while
I pressed" is exactly the saturated reasoning AGENTS.md rule 23 warns about.
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from peeklib import Peeker, PeekError          # noqa: E402

LOGS = os.path.join(HERE, "logs")

W_LOCKREQ = 0x40008D2C      # b0 = APP_lock_request_input
W_R74 = 0x40008E74          # bits 9|10 = Path A level memory + edge event
W_LOCKCMD = 0x40002E70      # b0 = APP_lock_command
CELLS = [W_LOCKREQ, W_R74, W_LOCKCMD]

EDGE_MASK = 0x600           # bits 9|10, proven by literal constants


def stimulus(cmd, presses, hold, gap, settle=1.0):
    """`cmd` in {lock, unlock, idle}.  idle => the stream only, no commands."""
    log = os.path.join(LOGS, "%s_%s_stim.log"
                       % (time.strftime("%Y%m%dT%H%M%S"), cmd))
    if cmd == "idle":
        secs = settle * 2 + presses * (hold + gap)
        args = ["baseline", "--secs", "%.2f" % secs]
    else:
        args = ["press", "--cmd", cmd, "--n", str(presses),
                "--hold", str(hold), "--gap", str(gap),
                "--settle", str(settle)]
    return subprocess.Popen(
        [sys.executable, os.path.join(HERE, "rfa_sim.py")] + args,
        stdout=open(log, "w"), stderr=subprocess.STDOUT), log


def run_condition(p, cmd, presses, hold, gap):
    proc, log = stimulus(cmd, presses, hold, gap)
    t0 = time.time()
    last, initial, trace = {}, {}, []
    n = 0
    while proc.poll() is None:
        for c in CELLS:
            try:
                v = p.read32(c)
            except PeekError:
                continue
            n += 1
            t = round(time.time() - t0, 3)
            if c not in last:
                initial[c] = v          # NOT an edge (bench_session_2 §8.1)
                last[c] = v
                continue
            if v != last[c]:
                trace.append((t, c, v))
                last[c] = v
    dur = time.time() - t0

    lockreq_rises = [t for t, c, v in trace
                     if c == W_LOCKREQ and (v >> 24) & 0xFF == 1]
    edge_sets = [t for t, c, v in trace
                 if c == W_R74 and (v & EDGE_MASK)]
    cmd_edges = [(t, (v >> 24) & 0xFF) for t, c, v in trace if c == W_LOCKCMD]
    return dict(cmd=cmd, dur=round(dur, 2), reads=n,
                rate=round(n / dur / len(CELLS), 1),
                initial={hex(k): hex(v) for k, v in initial.items()},
                lockreq_rises=lockreq_rises,
                r74_edge_sets=edge_sets,
                lockcmd_edges=cmd_edges,
                trace=[[t, hex(c), hex(v)] for t, c, v in trace],
                stim_log=log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--presses", type=int, default=6)
    ap.add_argument("--hold", type=float, default=0.30)
    ap.add_argument("--gap", type=float, default=1.20)
    ap.add_argument("--repeats", type=int, default=2)
    a = ap.parse_args()

    conds = ["lock", "unlock", "idle"] * a.repeats
    random.shuffle(conds)               # order must not confound the result
    print("condition order (randomised): %s\n" % conds)

    results = []
    with Peeker() as p:
        p.assert_live()
        for i, c in enumerate(conds):
            print("[%d/%d] %s ..." % (i + 1, len(conds), c), end="", flush=True)
            r = run_condition(p, c, a.presses, a.hold, a.gap)
            results.append(r)
            print(" %.1fs @%.1f Hz/cell | lockreq rises=%d | r74 bits9|10=%d"
                  " | lockcmd edges=%d"
                  % (r["dur"], r["rate"], len(r["lockreq_rises"]),
                     len(r["r74_edge_sets"]), len(r["lockcmd_edges"])))
            time.sleep(2.0)

    print("\n" + "=" * 68)
    print("RESULTS BY CONDITION (summed over repeats)")
    agg = {}
    for r in results:
        d = agg.setdefault(r["cmd"], dict(n=0, secs=0.0, rises=0, edges=0,
                                          cmds=0))
        d["n"] += 1
        d["secs"] += r["dur"]
        d["rises"] += len(r["lockreq_rises"])
        d["edges"] += len(r["r74_edge_sets"])
        d["cmds"] += len(r["lockcmd_edges"])
    for c in ("lock", "unlock", "idle"):
        if c not in agg:
            continue
        d = agg[c]
        print("  %-7s %d runs %5.1f s | lock_request_input rises %2d"
              " | r74 bits9|10 %2d | lock_command edges %2d"
              % (c, d["n"], d["secs"], d["rises"], d["edges"], d["cmds"]))

    print("\n" + "=" * 68)
    press_r = agg.get("lock", {}).get("rises", 0) + \
        agg.get("unlock", {}).get("rises", 0)
    idle_r = agg.get("idle", {}).get("rises", 0)
    press_s = agg.get("lock", {}).get("secs", 0) + \
        agg.get("unlock", {}).get("secs", 0)
    idle_s = agg.get("idle", {}).get("secs", 0) or 1.0
    pr = press_r / (press_s or 1.0)
    ir = idle_r / idle_s
    print("ADJUDICATION")
    print("  lock_request_input rise RATE:  pressed %.2f/s   idle %.2f/s"
          % (pr, ir))
    if press_r == 0:
        print("  => INCONCLUSIVE: the cell never rose even under presses.")
        print("     Check the stimulus logs before reading anything into this")
        print("     (AGENTS.md rule 27).")
    elif idle_r == 0:
        print("  => H_RKE supported: Path A's input rises ONLY when an RKE")
        print("     command is sent. The 'Path A is not RKE' claim in")
        print("     central_locking_chain.md §1 does not survive this.")
    elif ir >= pr * 0.5:
        print("  => H_COINC supported: the cell rises at a comparable rate")
        print("     with NO command sent. Presses are not what drives it;")
        print("     any press-time correlation is coincidence (rule 23).")
    else:
        print("  => PARTIAL: pressed rate exceeds idle but idle is non-zero.")
        print("     Both a press-driven and a background driver are present;")
        print("     do not attribute individual events to the press.")
    print("=" * 68)

    os.makedirs(LOGS, exist_ok=True)
    out = os.path.join(LOGS, "%s_patha_rke.json" % time.strftime("%Y%m%dT%H%M%S"))
    with open(out, "w") as fh:
        json.dump(dict(order=conds, aggregate=agg, runs=results,
                       edge_mask=hex(EDGE_MASK)), fh, indent=2)
    print("\nwrote %s" % out)


if __name__ == "__main__":
    main()
