#!/usr/bin/env python3
"""What triggers APP_req_word_74 b2 (0x40008E76) -> 0x06 ?

OBSERVATION TO EXPLAIN (docs/bench_session_2.md 6.3): the cell fires ONCE per
burst, not once per press - seen at t=6.620 s (3-probe run) and t=4.899 s
(17-probe run), each with three lock presses.

CANDIDATE HYPOTHESES, each with a DISTINCT prediction:

  H1 FIRST-PRESS      it fires on the first press of a burst and then latches.
                      -> fires once regardless of press count; time-to-fire is
                         CONSTANT from burst start.
  H2 LAST-PRESS/IDLE  it fires when the press train STOPS (a release/idle
                      timeout).
                      -> time-to-fire scales with press count and gap; it
                         follows the LAST press by a fixed delay.
  H3 N-TH PRESS       it needs a specific number of presses (e.g. 3).
                      -> 1 and 2 presses NEVER fire; 3+ always do.
  H4 FREE-RUNNING     it is periodic and unrelated to the stimulus.
                      -> fires in a NO-PRESS control too.

H4 is the one that would invalidate everything, so it is tested FIRST and with
the same duration as the real trials (rule 23: measure the unrelated case).

Method: for each condition, poll only 0x4099 (plus 0x0631 as a liveness
reference) at ~50 Hz, record the exact time of the 00->06 edge relative to
burst start AND to the last press, and repeat for replication.

Output: work/bench/logs/r74_trigger.json
"""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
LOGS = os.path.join(ROOT, "work/bench/logs")
OUT = os.path.join(LOGS, "r74_trigger.json")
TESTER_ID, ECU_ID = 0x726, 0x72E
DID_R74 = 0x4099          # 0x40008E76  req_word_74 b2
DID_LOCK = 0x0631         # 0x40002E70  APP_lock_command (liveness reference)


class Uds:
    def __init__(self, iface="can0"):
        self.s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.s.bind((iface,))
        self.s.settimeout(0.3)

    def send(self, cid, data):
        self.s.send(struct.pack("=IB3x8s", cid, 8, data + b"\x00" * (8 - len(data))))

    def drain(self):
        self.s.settimeout(0.001)
        while True:
            try:
                self.s.recv(16)
            except Exception:
                break

    def read_did(self, did, to=0.05):
        self.drain()
        self.s.settimeout(to)
        self.send(TESTER_ID, bytes([0x03, 0x22, (did >> 8) & 0xFF, did & 0xFF]))
        t0 = time.time()
        while time.time() - t0 < to:
            try:
                raw = self.s.recv(16)
            except Exception:
                break
            cid, dlc, d = struct.unpack("=IB3x8s", raw)
            if (cid & 0x1FFFFFFF) != ECU_ID:
                continue
            if d[0] >> 4 == 0:
                n = d[0] & 0x0F
                b = d[1:1 + n]
                if b and b[0] == 0x62:
                    return b[3:].hex().upper()
                return None
        return None

    def wake(self):
        for _ in range(10):
            self.send(TESTER_ID, bytes([0x02, 0x3E, 0x80]))
            time.sleep(0.2)


def trial(u, presses, gap, secs, label, cmd="lock"):
    """Run one condition; return the r74 edge times relative to burst start."""
    pr = None
    press_marks = []
    if presses > 0:
        pr = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "work/bench/rfa_sim.py"),
             "press", "--cmd", cmd, "--n", str(presses), "--gap", str(gap),
             "--key-outside"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    trace_r74, trace_lock = [], []
    while time.time() - t0 < secs:
        v = u.read_did(DID_R74)
        if v is not None:
            t = round(time.time() - t0, 3)
            if not trace_r74 or trace_r74[-1][1] != v:
                trace_r74.append((t, v))
        v = u.read_did(DID_LOCK)
        if v is not None:
            t = round(time.time() - t0, 3)
            if not trace_lock or trace_lock[-1][1] != v:
                trace_lock.append((t, v))
    if pr:
        pr.wait(timeout=60)
    edges = [t for t, v in trace_r74 if v == "06"]
    # liveness: did the stimulus visibly reach the ECU at all?
    lock_events = [t for t, v in trace_lock if v == "01"]
    return dict(label=label, presses=presses, gap=gap, secs=secs,
                r74_trace=trace_r74, lock_trace=trace_lock,
                r74_edges=edges, lock_events=lock_events,
                fired=len(edges), stimulus_seen=len(lock_events))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=2)
    a = ap.parse_args()
    u = Uds()
    u.wake()
    results = []

    print("== H4 first: does it fire with NO stimulus? ==")
    print("   (rule 23 - a result means nothing until the unrelated case is measured)")
    for r in range(a.reps):
        res = trial(u, 0, 0, 10.0, "no-press")
        results.append(res)
        print("   rep%d  no-press 10s : r74 fired %d time(s), lock events %d"
              % (r, res["fired"], res["stimulus_seen"]))
        if res["fired"]:
            print("      edges at %s" % res["r74_edges"])

    print("\n== press-count series (gap fixed at 1.5 s) ==")
    for n in (1, 2, 3, 5):
        for r in range(a.reps):
            res = trial(u, n, 1.5, 4.0 + n * 2.0, "n=%d" % n)
            results.append(res)
            rel = ""
            if res["r74_edges"] and res["lock_events"]:
                rel = "  first edge %+.3f s after LAST lock event" % (
                    res["r74_edges"][0] - res["lock_events"][-1])
            print("   n=%d rep%d : fired %d, stimulus %d, edges %s%s"
                  % (n, r, res["fired"], res["stimulus_seen"],
                     res["r74_edges"][:3], rel))

    print("\n== gap series (3 presses) ==")
    for g in (0.6, 2.5):
        for r in range(a.reps):
            res = trial(u, 3, g, 12.0, "gap=%.1f" % g)
            results.append(res)
            print("   gap=%.1f rep%d : fired %d, edges %s, last lock %s"
                  % (g, r, res["fired"], res["r74_edges"][:3],
                     ("%.3f" % res["lock_events"][-1]) if res["lock_events"] else "-"))

    os.makedirs(LOGS, exist_ok=True)
    json.dump(results, open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)

    # ---------------- verdict ----------------
    print("\n== VERDICT ==")
    ctrl = [r for r in results if r["presses"] == 0]
    ctrl_fired = sum(r["fired"] for r in ctrl)
    print("   H4 free-running : control fired %d time(s) in %d rep(s)"
          % (ctrl_fired, len(ctrl)))
    if ctrl_fired:
        print("      ⇒ H4 NOT EXCLUDED - the cell moves without any stimulus.")
        print("        Every press-condition result below is confounded.")
    else:
        print("      ⇒ H4 excluded (no spontaneous firing observed)")

    byn = {}
    for r in results:
        if r["presses"] > 0 and r["gap"] == 1.5:
            byn.setdefault(r["presses"], []).append(r["fired"])
    print("   press count -> times fired: %s"
          % {k: v for k, v in sorted(byn.items())})
    never = [k for k, v in byn.items() if all(x == 0 for x in v)]
    always = [k for k, v in byn.items() if all(x > 0 for x in v)]
    print("      never fires at n=%s ; always fires at n=%s" % (never, always))
    if never and always and max(never) < min(always):
        print("      ⇒ consistent with H3 (needs >= %d presses)" % min(always))
    elif always and not never:
        print("      ⇒ fires at every press count - H3 unlikely")

    lags = []
    for r in results:
        if r["r74_edges"] and r["lock_events"]:
            lags.append(r["r74_edges"][0] - r["lock_events"][-1])
    if lags:
        print("   lag from LAST lock event to first edge: min %+.3f max %+.3f"
              % (min(lags), max(lags)))
        if max(lags) - min(lags) < 0.35:
            print("      ⇒ constant lag after the last press - supports H2")
        else:
            print("      ⇒ lag varies - H2 not supported as stated")
    starts = [r["r74_edges"][0] for r in results if r["r74_edges"]]
    if starts:
        print("   time from BURST START to first edge: min %.3f max %.3f"
              % (min(starts), max(starts)))
        if max(starts) - min(starts) < 0.35:
            print("      ⇒ constant from burst start - supports H1")


if __name__ == "__main__":
    main()
