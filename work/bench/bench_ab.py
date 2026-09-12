#!/usr/bin/env python3
"""Simultaneous CAN + audio trial: does the relay click when d3/strobe says so?

Runs candump and parecord together, drives a chosen RKE command, then aligns the
ACOUSTIC click train against the CAN EXECUTE-STROBE train and reports the fit.

Why align rather than assume t=0: candump stamps with the host clock, while the
audio stream begins whenever the recorder actually opens the device (tens to
hundreds of ms later, and not constant).  So the offset is MEASURED by
cross-correlation and printed.  Two guards keep that honest:

  * the fitted offset must be small and plausible (<2 s).  A large "best" offset
    means the alignment found noise, not the signal.
  * a SHUFFLE control: the same matcher is run against randomised click times.
    If random times match nearly as well, the match carries no information
    (AGENTS.md rule 23 - a result means nothing until you measure what unrelated
    input scores).

What this can establish
  * that the d1 bit6 execute strobe corresponds 1:1 to a physical actuation
  * whether d3=06 (the new third command) actuates the lock hardware AT ALL,
    which pure CAN observation cannot tell us

usage: bench_ab.py --nibble 1 --presses 3
"""
import argparse
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from click_detect import detect  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "logs")
LINE = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-F]{3})\s+\[(\d+)\]\s+(.*)")
IDLE = [0x02, 0x17, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00]


def tx(sock, cid, data):
    sock.send(struct.pack("=IB3x8s", cid, len(data), bytes(data).ljust(8, b"\0")))


def run(a):
    os.makedirs(LOGS, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    canlog = os.path.join(LOGS, "%s_ab_nib%d.log" % (stamp, a.nibble))
    wav = os.path.join(LOGS, "%s_ab_nib%d.wav" % (stamp, a.nibble))

    cap = subprocess.Popen(["candump", "-ta", a.iface],
                           stdout=open(canlog, "w"), stderr=subprocess.DEVNULL)
    rec = subprocess.Popen(["parecord", "--channels=1", "--rate=48000",
                            "--format=s16le", "--file-format=wav", wav],
                           stderr=subprocess.DEVNULL)
    time.sleep(1.0)                      # let both settle

    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((a.iface,))

    def idle(secs):
        f = list(IDLE); f[1] |= 0x80
        end = time.time() + secs
        while time.time() < end:
            tx(s, 0x100, f); time.sleep(0.06)

    def press(secs):
        f = list(IDLE); f[1] |= 0x80
        f[6] = (0x1F << 3) & 0xFF
        f[7] = a.nibble & 0xFF
        end = time.time() + secs
        while time.time() < end:
            tx(s, 0x100, f); time.sleep(0.06)

    t_press = []
    idle(a.settle)
    for _ in range(a.presses):
        t_press.append(time.time())
        press(a.hold)
        idle(a.gap)
    idle(1.5)

    time.sleep(0.5)
    cap.send_signal(signal.SIGINT); cap.wait(timeout=5)
    rec.terminate()
    try:
        rec.wait(timeout=5)
    except subprocess.TimeoutExpired:
        rec.kill()

    # ---- CAN side: the execute-strobe train -------------------------------
    strobes, lock_frames = [], []
    with open(canlog) as fh:
        for ln in fh:
            m = LINE.match(ln.strip())
            if not m:
                continue
            t, _, cid, _, data = m.groups()
            if int(cid, 16) != 0x03A:
                continue
            d = [int(x, 16) for x in data.split()]
            lock_frames.append((float(t), d))
            if len(d) > 1 and d[1] & 0x40:
                strobes.append((float(t), d[3] if len(d) > 3 else None))
    if not lock_frames:
        print("no 0x3A frames captured - is the bus awake?")
        return
    t_can0 = lock_frames[0][0]
    strobe_rel = [t - t_can0 for t, _ in strobes]

    # ---- audio side: the click train --------------------------------------
    det = detect(wav, k=a.k)
    # ⚠ Two ACOUSTIC CLASSES are present, and mixing them destroys the fit.
    # The relay actuation is a loud transient (snr ~300-400); there is also a
    # quiet class (snr ~9) - most likely the relay RELEASING, or mechanical
    # settle.  Including the quiet class let the matcher pair strobes with the
    # wrong events, inflating the tolerance needed from ~20 ms to ~250 ms and
    # making the result indistinguishable from shuffled noise.  Separate them by
    # amplitude and match on the loud class only; both counts are reported.
    loud = [e for e in det["events"] if e["snr"] >= a.snr_min]
    quiet = [e for e in det["events"] if e["snr"] < a.snr_min]
    clicks = [e["t"] for e in loud]

    # ⚠ ROOM-NOISE / DEGENERATE-AUDIO GUARD.  Talking, handling the bench, or a
    # muted source all produce many "events" that are not relay actuations.  A
    # trial with far more loud events than strobes, or a degenerate threshold,
    # is CONTAMINATED and must be discarded - not analysed and reported.
    contaminated = det.get("degenerate") or (
        len(clicks) > 3 * max(len(strobes), 1))
    if contaminated:
        print("=== AUDIO REJECTED ===")
        print("  degenerate threshold : %s" % det.get("degenerate"))
        print("  loud events / strobes: %d / %d" % (len(clicks), len(strobes)))
        print("  ⇒ the acoustic channel is contaminated (room noise, handling,")
        print("    or a silent/muted source). DISCARD this trial and re-run in a")
        print("    quiet room. No acoustic conclusion is drawn.")
        print("  CAN-side result still stands:")
        for t, v in strobes:
            print("     strobe t=%7.3f  d3=%s"
                  % (t - t_can0, hex(v) if v is not None else "?"))
        return

    # ---- alignment by cross-correlation -----------------------------------
    def score(offset, cl, st, tol):
        used, n = set(), 0
        for t in st:
            best, bi = tol, None
            for i, c in enumerate(cl):
                if i in used:
                    continue
                dt = abs((c - offset) - t)
                if dt < best:
                    best, bi = dt, i
            if bi is not None:
                used.add(bi); n += 1
        return n

    tol = a.tol
    grid = np.arange(-2.0, 2.0, 0.001)
    scores = [score(o, clicks, strobe_rel, tol) for o in grid]
    best_i = int(np.argmax(scores)) if scores else 0
    best_off = float(grid[best_i]) if scores else 0.0
    best_n = int(scores[best_i]) if scores else 0

    # ---- shuffle control (rule 23) ----------------------------------------
    rng = np.random.default_rng(0)
    dur = det["duration"] or 1.0
    ctrl = []
    for _ in range(200):
        fake = sorted(rng.uniform(0, dur, len(clicks)))
        ctrl.append(max(score(o, fake, strobe_rel, tol) for o in grid[::10]))
    ctrl_mean = float(np.mean(ctrl)) if ctrl else 0.0
    ctrl_max = int(np.max(ctrl)) if ctrl else 0

    print("=== CAN ===")
    print("  0x3A frames      : %d" % len(lock_frames))
    print("  execute strobes  : %d   d3 values: %s"
          % (len(strobes), sorted({hex(v) for _, v in strobes if v is not None})))
    for t, v in strobes:
        print("     strobe t=%7.3f  d3=%s" % (t - t_can0, hex(v) if v is not None else "?"))
    print("=== AUDIO ===")
    print("  duration %.2fs  threshold=%.6f (median+%.0f*MAD)"
          % (det["duration"], det["threshold"], det["k"]))
    print("  clicks detected  : %d" % len(clicks))
    for e in det["events"]:
        print("     click  t=%7.3f  snr=%.1f" % (e["t"], e["snr"]))
    print("=== ALIGNMENT ===")
    print("  best offset      : %+.3f s" % best_off)
    print("  strobes matched  : %d / %d  (tol +-%.0f ms)"
          % (best_n, len(strobe_rel), tol * 1000))
    print("  shuffle control  : mean %.2f, max %d  (random clicks)"
          % (ctrl_mean, ctrl_max))
    if abs(best_off) > 1.9:
        print("  ⚠ offset at the search edge - alignment is NOT trustworthy")
    elif best_n == 0:
        print("  ⇒ NO acoustic correlate: strobes fired but nothing was heard")
    elif best_n > ctrl_max:
        print("  ⇒ SIGNAL: matches exceed every one of 200 shuffled controls")
    else:
        print("  ⇒ NOT DISCRIMINATING: shuffled clicks score as well - no conclusion")

    out = canlog.replace(".log", ".json")
    with open(out, "w") as fh:
        json.dump(dict(nibble=a.nibble, presses=a.presses,
                       strobes=[dict(t=t - t_can0, d3=v) for t, v in strobes],
                       clicks=det["events"], best_offset=best_off,
                       matched=best_n, n_strobes=len(strobe_rel),
                       shuffle_mean=ctrl_mean, shuffle_max=ctrl_max,
                       wav=wav, canlog=canlog), fh, indent=1)
    print("\n  can: %s\n  wav: %s\n  json: %s" % (canlog, wav, out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="can1")
    ap.add_argument("--nibble", type=int, default=1)
    ap.add_argument("--presses", type=int, default=3)
    ap.add_argument("--hold", type=float, default=0.4)
    ap.add_argument("--gap", type=float, default=2.0)
    ap.add_argument("--settle", type=float, default=2.5)
    ap.add_argument("--k", type=float, default=8.0)
    ap.add_argument("--snr-min", type=float, default=100.0,
                    help="amplitude split: relay actuations are snr~300+, a "
                         "quiet class sits near snr~9 (see the note in run())")
    ap.add_argument("--tol", type=float, default=0.05,
                    help="match tolerance, s. With the loud class only the "
                         "residuals are <=21 ms, so 50 ms is generous; a value "
                         "like 250 ms matches shuffled noise just as well.")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
