#!/usr/bin/env python3
"""Differential RAM scan: find EVERY cell that moves under an RKE press.

Item 41 ("which of the 33 `req_word_74` readers actuates the lock") has been
attacked statically until every instrument in that code region is saturated
(docs/rke_lock_join.md §5) and with a 17-cell probe bank whose addresses had to
be chosen *before* flashing (docs/bench_session_2.md).  The peek service removes
that constraint: any address, no reflash.  So stop guessing addresses and
measure which ones move.

METHOD
  Phase Q1 : sweep the region N times with NO stimulus.
  Phase S  : sweep while `rfa_sim.py press` drives lock presses on MS-CAN.
  Phase Q2 : sweep again with no stimulus.

  A cell is STIMULUS-DRIVEN only if (i) it is CONSTANT across every quiet pass,
  and (ii) it shows the same novel value in >= MIN_HITS separate stimulus
  passes.  Both halves matter:

    (i)  excludes free-running cells.  A cell that wanders through many values
         on its own will always show some value "not seen in quiet" -- that is
         coverage, not agreement (AGENTS.md rule 9).  In the first run of this
         script 11 of 28 "hits" were of exactly that kind.
    (ii) excludes one-off transport/timing flukes.

⚠ THIS SCAN HAS MEASURABLE, LIMITED DETECTION POWER, and it reports it.
  Each cell is sampled ONCE PER PASS (~5 s apart), so a cell that is only in
  its active state for a fraction `duty` of the time is missed entirely with
  probability (1-duty)^passes.  `APP_lock_command` has a measured duty of ~38%
  under this stimulus (work/bench/276), so 6 passes miss it ~6% of the time --
  and in the first run it did exactly that, failing C1.  The script therefore
  prints an EMPIRICAL sensitivity figure from the known positive control, and
  a null result is only ever a statement about cells with a duty high enough
  for that sensitivity.  Candidates from here are LEADS, to be confirmed at
  high rate by `276_peek_wire_watch.py` -- never published from this script
  alone.

WHY Q2 EXISTS (docs/bench_session_2.md §8.1): the `r74_trigger` sweep ran its
null control first, for 10 s, before any press -- structurally blind to a
mechanism that is armed by a press and then free-runs.  Quiet is measured on
BOTH sides here, for a duration comparable to the stimulus phase.

CONTROLS (the run is void if any fails)
  C1 positive : `APP_lock_command` 0x40002E70 is known to move on a lock press
                (proven against MS 0x3A d3, session 2 §3).  It MUST appear in
                the stimulus-driven set.  If it does not, the stimulus did not
                fire and NOTHING else in the output means anything (rule 27).
  C2 negative : a flash address never changes.  If it does, the instrument is
                lying.
  C3 liveness : the self-referential request-buffer peek (rule 36).

Usage:
  python3 work/bench/275_ram_diff_scan.py            # default region + presses
  python3 work/bench/275_ram_diff_scan.py --quick
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

# Regions worth sweeping, from the chain doc.  Every address the project has
# named for the lock/RKE chain lies in one of these two windows.
REGIONS = [
    ("body_struct", 0x40008C00, 0x40009100),   # the shared body-control struct
    ("rke_lockcmd", 0x40002D00, 0x40002F00),   # rke_command_code .. lock_command
]

C1_POSITIVE = 0x40002E70        # APP_lock_command -- must move
C2_NEGATIVE = 0x000DE278        # flash -- must not move

NAMED = {
    0x40002DA2: "APP_rke_command_code",
    0x40002E70: "APP_lock_command",
    0x40002E44: "timed-feature output (item 42)",
    0x40008D2C: "APP_lock_request_input",
    0x40008D3A: "APP_rke_join_gate",
    0x40008D6B: "APP_lock_src_origin",
    0x40008E58: "APP_body_cmd_bus",
    0x40008E70: "APP_req_word_70",
    0x40008E74: "APP_req_word_74",
    0x40008EF7: "APP_lock_src_level",
    0x40009034: "APP_rke_cmd_bits_34",
    0x40009038: "APP_rke_cmd_bits_38",
}


def sweep(p, addrs):
    """One pass over the address list.  Returns {addr: value}."""
    out = {}
    for a in addrs:
        try:
            out[a] = p.read32(a)
        except PeekError as e:
            out[a] = "ERR:%s" % e
    return out


def collect(p, addrs, passes, label):
    """`passes` sweeps.  Returns a LIST of per-pass snapshots.

    Per-pass structure is kept (rather than a merged set) so the classifier can
    require a value to recur across passes, and so detection power can be
    measured from the positive control.
    """
    snaps = []
    t0 = time.time()
    for i in range(passes):
        snaps.append(sweep(p, addrs))
        print("    %s pass %d/%d  (%.1f s)" % (label, i + 1, passes,
                                               time.time() - t0))
    return snaps


def start_stimulus(n, hold, gap):
    """rfa_sim press in the background.  Returns the Popen."""
    os.makedirs(LOGS, exist_ok=True)
    log = os.path.join(LOGS, "%s_ramdiff_stim.log" % time.strftime("%Y%m%dT%H%M%S"))
    cmd = [sys.executable, os.path.join(HERE, "rfa_sim.py"), "press",
           "--cmd", "lock", "--n", str(n), "--hold", str(hold),
           "--gap", str(gap), "--settle", "1.0"]
    return subprocess.Popen(cmd, stdout=open(log, "w"),
                            stderr=subprocess.STDOUT), log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--passes", type=int, default=4)
    ap.add_argument("--stim-passes", type=int, default=6)
    ap.add_argument("--presses", type=int, default=20)
    ap.add_argument("--hold", type=float, default=0.30)
    ap.add_argument("--gap", type=float, default=1.20)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    if a.quick:
        a.passes, a.stim_passes, a.presses = 2, 3, 10

    addrs = []
    for _, lo, hi in REGIONS:
        addrs += list(range(lo, hi, 4))
    if C2_NEGATIVE not in addrs:
        addrs.append(C2_NEGATIVE)
    print("sweeping %d words (%d bytes) over %d regions"
          % (len(addrs), 4 * len(addrs), len(REGIONS)))

    with Peeker() as p:
        p.assert_live()                                   # C3
        hz = p.rate()
        print("peek rate %.1f Hz -> %.1f s per pass\n" % (hz, len(addrs) / hz))

        print("== phase Q1: quiet (no stimulus) ==")
        q1 = collect(p, addrs, a.passes, "Q1")

        print("\n== phase S: RKE lock presses on can1 ==")
        stim, stimlog = start_stimulus(a.presses, a.hold, a.gap)
        time.sleep(1.5)
        s = collect(p, addrs, a.stim_passes, "S ")
        stim.wait(timeout=180)
        print("    stimulus log: %s" % stimlog)

        print("\n== phase Q2: quiet again (the control §8.1 lacked) ==")
        time.sleep(3.0)
        q2 = collect(p, addrs, a.passes, "Q2")

    # A read error is NOT a value.  Mixing "ERR:..." into the value sets would
    # both break ordering and, worse, let a transport hiccup masquerade as a
    # stimulus-driven change.  Drop errored cells and report them separately.
    def allvals(x):
        out = []
        for snaps in (q1, s, q2):
            out += [sn[x] for sn in snaps]
        return out

    errored = sorted({x for x in addrs
                      if any(isinstance(v, str) for v in allvals(x))})
    live = [x for x in addrs if x not in set(errored)]

    def qset(x):
        return {sn[x] for sn in q1} | {sn[x] for sn in q2}

    quiet = {x: qset(x) for x in live}
    free_running = {x: sorted(quiet[x]) for x in live if len(quiet[x]) > 1}

    # Candidate = CONSTANT in quiet, and a novel value recurring in >= MIN_HITS
    # stimulus passes.  See the module docstring for why both clauses exist.
    MIN_HITS = 2 if a.stim_passes >= 4 else 1
    cand = {}
    for x in live:
        if len(quiet[x]) != 1:
            continue                       # free-running: undiscriminating
        base = next(iter(quiet[x]))
        hits = {}
        for sn in s:
            v = sn[x]
            if v != base:
                hits[v] = hits.get(v, 0) + 1
        best = {v: c for v, c in hits.items() if c >= MIN_HITS}
        if best:
            cand[x] = dict(base=base, hits=best,
                           n_active=sum(best.values()),
                           duty=sum(best.values()) / float(a.stim_passes))

    # --------------------------------------------------------- the controls
    c1w = C1_POSITIVE & ~3          # the word containing the byte
    ok_c1 = c1w in cand
    ok_c2 = (C2_NEGATIVE not in cand
             and len(quiet.get(C2_NEGATIVE, set())) == 1)

    # EMPIRICAL DETECTION POWER, from the positive control itself.
    if ok_c1:
        obs_duty = cand[c1w]["duty"]
        p_miss = (1.0 - obs_duty) ** a.stim_passes
    else:
        obs_duty, p_miss = 0.0, 1.0

    print("\n" + "=" * 64)
    print("CONTROLS")
    print("  C1 positive  APP_lock_command 0x%08X moves under stimulus : %s"
          % (c1w, "PASS" if ok_c1 else "FAIL"))
    print("  C2 negative  flash 0x%08X constant                        : %s"
          % (C2_NEGATIVE, "PASS" if ok_c2 else "FAIL"))
    print("\nDETECTION POWER (measured, not assumed)")
    print("  positive control active in %d/%d stimulus passes (duty %.0f%%)"
          % (cand.get(c1w, {}).get("n_active", 0), a.stim_passes,
             100 * obs_duty))
    print("  => a cell with that duty is MISSED with probability %.1f%%"
          % (100 * p_miss))
    print("  => a NULL here is only a claim about cells of comparable duty.")
    if not ok_c1:
        print("\n!! C1 FAILED. Check the stimulus log before reading anything")
        print("   below: if the presses fired, this is under-sampling, not a")
        print("   negative (AGENTS.md rule 27). Raise --stim-passes.")
    print("=" * 64)

    if errored:
        print("\nERRORED cells (excluded, not a result): %d  e.g. %s"
              % (len(errored), [hex(x) for x in errored[:6]]))

    print("\nCANDIDATES: constant in quiet, novel value in >=%d stim passes: %d"
          % (MIN_HITS, len(cand)))
    for x in sorted(cand, key=lambda k: -cand[k]["n_active"]):
        c = cand[x]
        print("  0x%08X  %-28s  quiet=0x%X  stim=%s  (%d/%d passes)"
              % (x, NAMED.get(x, ""), c["base"],
                 ", ".join("0x%X x%d" % (v, n)
                           for v, n in sorted(c["hits"].items())),
                 c["n_active"], a.stim_passes))

    print("\nFREE-RUNNING cells (move in quiet -- EXCLUDED, not a result): %d"
          % len(free_running))
    for x in sorted(free_running)[:20]:
        print("  0x%08X  %-28s  %s"
              % (x, NAMED.get(x, ""), [hex(v) for v in free_running[x]][:5]))

    print("\n⚠ Candidates are LEADS. Confirm each at high rate against the wire"
          "\n  with 276_peek_wire_watch.py before treating it as a finding.")

    os.makedirs(LOGS, exist_ok=True)
    out = os.path.join(LOGS, "%s_ramdiff.json" % time.strftime("%Y%m%dT%H%M%S"))
    with open(out, "w") as fh:
        json.dump(dict(
            controls=dict(c1_positive=ok_c1, c2_negative=ok_c2),
            detection_power=dict(control_duty=obs_duty, p_miss=p_miss,
                                 min_hits=MIN_HITS),
            regions=[[n, hex(lo), hex(hi)] for n, lo, hi in REGIONS],
            passes=dict(q1=a.passes, s=a.stim_passes, q2=a.passes),
            stimulus=dict(presses=a.presses, hold=a.hold, gap=a.gap),
            candidates={hex(k): dict(base=hex(v["base"]),
                                     hits={hex(vv): n
                                           for vv, n in v["hits"].items()},
                                     n_active=v["n_active"])
                        for k, v in cand.items()},
            errored=[hex(x) for x in errored],
            quiet_values={hex(k): [hex(x) for x in sorted(v)]
                          for k, v in quiet.items() if len(v) > 1},
            named={hex(k): v for k, v in NAMED.items()},
        ), fh, indent=2)
    print("\nwrote %s" % out)
    return 0 if (ok_c1 and ok_c2) else 1


if __name__ == "__main__":
    sys.exit(main())
