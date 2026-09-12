#!/usr/bin/env python3
"""Beat the round-robin ordering floor: ONE peeked cell vs the WIRE.

THE PROBLEM (docs/bench_session_3.md §5, §7)
`279` polls 2 cells round-robin, so any one cell is sampled every ~23 ms and no
ordering finer than that is claimable.  It concluded `APP_lock_request_input`
and `APP_lock_command -> 02` are "simultaneous at the limit of this instrument"
-- true, but the limit was the instrument, not the firmware.

THE IMPROVEMENT
`APP_lock_command` is visible on MS-CAN `0x3A` d3 (proven three independent
ways; re-confirmed by 276's acceptance test).  So it does NOT need to be peeked
at all:

  channel A : peek ONE cell (0x40008D2C) -- no round-robin division, ~100 Hz,
              so ~10 ms sampling instead of ~23 ms.
  channel B : candump timestamps of 0x3A d3 -- an INDEPENDENT clock, sampled at
              the frame rate, not by us at all.

Two gains, and the second is the bigger one:
  1. sampling resolution 23 ms -> ~10 ms;
  2. with N independent press events the MEAN offset has standard error
     sigma/sqrt(N), so many events resolve a systematic offset far below the
     single-sample resolution.  A 10 ms quantisation with N=30 gives a standard
     error of order 2 ms.

⚠ WHAT THIS STILL CANNOT DO
It cannot beat the *latency skew* between the two channels: a peek reply is
observed when the UDS response arrives, a `0x3A` frame when candump sees it.
Any CONSTANT skew between those two paths is indistinguishable from a real lag
-- so this measures the offset PRECISELY but not necessarily ACCURATELY.

Therefore the verdict below is stated only as a BOUND unless the skew is
calibrated.  The calibration is the null pairing: `lock_command -> 01` and
`-> 02` are BOTH on the wire, so the wire-to-wire spacing of the triplet is
known exactly (0.51 s) and needs no peek.  If our measured
peek-vs-wire offset for the SAME logical event is X, then X is the skew
estimate, and only an offset significantly different from X is a real lag.

CONTROLS
  C1  the wire observer must be alive (rule 27: empty = INCONCLUSIVE).
  C2  the peek channel must show the documented rise/fall pattern.
  C3  RE-RUN AT TWO GAPS (rule 26) and pair against BOTH d3 values (rule 41).
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from peeklib import Peeker, PeekError          # noqa: E402

LOGS = os.path.join(HERE, "logs")
LOCK_ID = 0x03A
W_LOCKREQ = 0x40008D2C

RE_TA = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]{3})\s+\[(\d+)\]\s+(.*)")
RE_L = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]{3})#([0-9A-Fa-f]*)")


def parse_candump(path):
    out = []
    with open(path) as fh:
        for ln in fh:
            ln = ln.strip()
            m = RE_TA.match(ln)
            if m:
                t, _, cid, _, data = m.groups()
                out.append((float(t), int(cid, 16),
                            bytes(int(x, 16) for x in data.split())))
                continue
            m = RE_L.match(ln)
            if m:
                t, _, cid, data = m.groups()
                out.append((float(t), int(cid, 16), bytes.fromhex(data)))
    return out


def nearest(ea, eb, window=1.0):
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


def stats(v):
    if not v:
        return None
    n = len(v)
    m = sum(v) / n
    if n < 2:
        return dict(n=n, mean=m, sd=0.0, se=0.0)
    var = sum((x - m) ** 2 for x in v) / (n - 1)
    sd = var ** 0.5
    return dict(n=n, mean=m, sd=sd, se=sd / (n ** 0.5))


def run(p, gap, presses, hold):
    ts = time.strftime("%Y%m%dT%H%M%S")
    cap_path = os.path.join(LOGS, "%s_1cell_bus.log" % ts)
    cap = subprocess.Popen(["candump", "-ta", "can1"],
                           stdout=open(cap_path, "w"),
                           stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    stim_log = os.path.join(LOGS, "%s_1cell_stim.log" % ts)
    stim = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "rfa_sim.py"), "press",
         "--cmd", "lock", "--n", str(presses), "--hold", str(hold),
         "--gap", str(gap), "--settle", "1.0"],
        stdout=open(stim_log, "w"), stderr=subprocess.STDOUT)

    # t0 must be on the SAME clock as candump's timestamps.  candump -ta prints
    # CLOCK_REALTIME seconds, so time.time() is the right reference.
    #
    # ⚠ TIMESTAMP BIAS, and how it is removed.
    # Timestamping a transition when the REPLY ARRIVES is systematically late by
    # (a) the UDS round trip, and (b) up to one sample interval, since the
    # change happened somewhere between the previous look and this one.  With an
    # ~11 ms sample interval and a ~10 ms round trip that is a bias of order
    # +15 ms -- the same order as the effect being measured, i.e. enough to
    # manufacture a "lag" out of nothing.
    # Removal: record send AND reply time per sample; the instant the value
    # actually refers to is bracketed by those, best-estimated at their midpoint.
    # A transition seen at sample k then occurred between midpoint(k-1) and
    # midpoint(k), best-estimated at the mean of the two.  Both biases cancel.
    t0 = time.time()
    last = None
    last_mid = None
    rises, falls = [], []
    rtts = []
    n = 0
    while stim.poll() is None:
        t_send = time.time()
        try:
            v = p.read32(W_LOCKREQ)
        except PeekError:
            continue
        t_reply = time.time()
        rtts.append(t_reply - t_send)
        mid = 0.5 * (t_send + t_reply)
        n += 1
        b = (v >> 24) & 0xFF
        if last is None:
            last = b
            last_mid = mid
            continue
        if b != last:
            t_est = 0.5 * (last_mid + mid)      # de-biased transition estimate
            if b == 1:
                rises.append(t_est)
            elif last == 1:
                falls.append(t_est)
        last = b
        last_mid = mid
    dur = time.time() - t0
    time.sleep(0.4)
    cap.send_signal(signal.SIGINT)
    try:
        cap.wait(timeout=3)
    except subprocess.TimeoutExpired:
        cap.kill()

    frames = parse_candump(cap_path)
    lock = [(t, d) for t, c, d in frames if c == LOCK_ID and len(d) > 3]
    return dict(rate=n / dur, dur=dur, rises=rises, falls=falls,
                lock=lock, cap=cap_path, stim=stim_log,
                rtt_mean=(sum(rtts) / len(rtts)) if rtts else 0.0,
                rtt_max=max(rtts) if rtts else 0.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--presses", type=int, default=30)
    ap.add_argument("--hold", type=float, default=0.30)
    ap.add_argument("--gaps", default="1.2,0.7")
    a = ap.parse_args()
    gaps = [float(g) for g in a.gaps.split(",")]

    out = {}
    with Peeker() as p:
        p.assert_live()
        for g in gaps:
            print("\n=== gap %.2f s ===" % g)
            r = run(p, g, a.presses, a.hold)
            print("  peek %.1f Hz on ONE cell -> %.0f ms sampling"
                  " | RTT mean %.1f ms max %.1f ms (de-biased by midpoint)"
                  % (r["rate"], 1000.0 / max(r["rate"], 1),
                     1000 * r["rtt_mean"], 1000 * r["rtt_max"]))

            if not r["lock"]:
                print("  !! bus observer captured NOTHING -> INCONCLUSIVE"
                      " (rule 27), not a negative.")
                out[g] = dict(inconclusive=True)
                continue

            # wire edges, per d3 value
            edges = {1: [], 2: []}
            prev = None
            for t, d in r["lock"]:
                if prev is not None and d[3] != prev and d[3] in edges:
                    edges[d[3]].append(t)
                prev = d[3]
            print("  wire d3 edges: ->01 %d, ->02 %d | peek rises %d"
                  % (len(edges[1]), len(edges[2]), len(r["rises"])))

            res = {}
            for val in (1, 2):
                offs = nearest(r["rises"], edges[val])
                st = stats(offs)
                res[val] = st
                if st:
                    print("    rise vs d3->%02X : n=%2d  mean %+.4f s"
                          "  sd %.4f  SE %.4f"
                          % (val, st["n"], st["mean"], st["sd"], st["se"]))
            # wire-to-wire control: needs no peek at all
            ww = nearest(edges[1], edges[2])
            wwst = stats(ww)
            if wwst:
                print("    [wire-only control] d3->01 to d3->02 : n=%d"
                      " mean %+.4f s  sd %.4f"
                      % (wwst["n"], wwst["mean"], wwst["sd"]))
            out[g] = dict(rate=r["rate"], res={str(k): v for k, v in res.items()},
                          wire_only=wwst, cap=r["cap"], stim=r["stim"])
            time.sleep(2.0)

    print("\n" + "=" * 70)
    print("ADJUDICATION")
    good = {g: v for g, v in out.items() if not v.get("inconclusive")}
    if len(good) < 2:
        print("  INCONCLUSIVE: need a result at two gaps (rule 26).")
    else:
        best = {}
        for g, v in good.items():
            cand = {int(k): s for k, s in v["res"].items() if s}
            if not cand:
                continue
            b = min(cand, key=lambda k: abs(cand[k]["mean"]))
            best[g] = (b, cand[b])
            print("  gap %.2f: nearest partner d3->%02X  mean %+.4f s"
                  "  SE %.4f  (n=%d)"
                  % (g, b, cand[b]["mean"], cand[b]["se"], cand[b]["n"]))
        vals = [v[1]["mean"] for v in best.values()]
        parts = {v[0] for v in best.values()}
        if len(parts) > 1:
            print("\n  => MIXED: the nearest partner CHANGES with cadence."
                  "  No ordering claimable.")
        elif len(vals) >= 2 and max(vals) - min(vals) > 0.100:
            print("\n  => PHASE ARTIFACT: offset moved %.3f s across gaps"
                  " (rule 26)." % (max(vals) - min(vals)))
        else:
            m = sum(vals) / len(vals)
            se = max(v[1]["se"] for v in best.values())
            print("\n  => STABLE across cadences: mean %+.4f s (max SE %.4f)"
                  % (m, se))
            print("     ⚠ This is a PRECISE offset, not necessarily an ACCURATE")
            print("     one: a constant skew between the UDS-reply path and the")
            print("     candump path is indistinguishable from a real lag.")
            if abs(m) < 3 * se:
                print("     |mean| < 3*SE -> consistent with ZERO offset:")
                print("     the two are ONE event, now at ~%.0f ms precision."
                      % (1000 * se))
            else:
                print("     |mean| = %.1f x SE -> a systematic offset exists,"
                      % (abs(m) / se if se else 0))
                print("     but its SIGN is only meaningful once the channel")
                print("     skew is calibrated. Reported as a BOUND.")
    print("=" * 70)

    path = os.path.join(LOGS, "%s_1cell_order.json" % time.strftime("%Y%m%dT%H%M%S"))
    with open(path, "w") as fh:
        json.dump({str(k): v for k, v in out.items()}, fh, indent=2, default=str)
    print("\nwrote %s" % path)


if __name__ == "__main__":
    main()
