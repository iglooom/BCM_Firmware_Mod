#!/usr/bin/env python3
"""ONE short quiet trial, self-validating, with relay identification.

Designed for "tell me exactly when to be quiet" working: each invocation needs
only ~15 s of silence, announces a lead-in, auto-retries a contaminated take,
and classifies every click against REFERENCE relay signatures measured earlier.

What it answers per run: for RKE command <nibble>, (1) what does 0x3A d3 say,
(2) did a relay physically actuate, and (3) WHICH relay - lock or unlock -
identified acoustically, independently of CAN.

The reference signatures are not hardcoded: they are recomputed from a previous
trial's wav+json (default: the most recent nibble-1 run, which contains both
d3=01 and d3=02 strobes and separated 9/9 with p=0.005).

Validity rules, enforced before any conclusion is drawn:
  * degenerate threshold (MAD collapse)            -> RETRY
  * loud events >> strobes (room noise, handling)  -> RETRY
  * clean audio + zero clicks                      -> VALID NEGATIVE (reported
    as "no actuation", which is a real and interesting result, not a failure)

usage: quiet_trial.py --nibble 3 [--presses 3] [--retries 3]
"""
import argparse
import glob
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
from click_detect import detect, read_wav          # noqa: E402
from click_spectra import features, spectrum       # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "logs")
LINE = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-F]{3})\s+\[(\d+)\]\s+(.*)")
IDLE = [0x02, 0x17, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00]


def split_classes(events, edge_guard=0.05):
    """Separate relay actuations from the quiet class ADAPTIVELY.

    ⚠ Do NOT use a fixed `snr >= 100` cut.  `snr` is normalised by the
    recording's own noise floor, so the same physical relay scores ~410 in a
    quiet take and ~77 in a slightly noisier one.  A hardcoded cut therefore
    DROPPED FIVE REAL LOCK CLICKS in one run and made it look as though lock
    strobes never actuated - a false behavioural finding caused purely by the
    instrument (the same family as AGENTS.md rules 8/23).

    The two classes are separated by a large ratio gap in PEAK amplitude
    (observed 22x: 0.0017 for the quiet class vs 0.039+ for actuations), which
    is a property of the signal rather than of the noise floor.  Split at the
    largest ratio gap, and report it so the split is auditable.

    `edge_guard` drops events in the first N seconds: `parecord` emits a
    start-up transient at t~0.009 that is loud enough to survive any threshold
    but precedes every stimulus, so it can never be an actuation.
    """
    events = [e for e in events if e["t"] >= edge_guard]
    if not events:
        return [], [], None
    peaks = sorted(e["peak"] for e in events if e["peak"] > 0)
    if len(peaks) < 2:
        # A lone event cannot define a split.  Judge it against the actuation
        # amplitude seen on this rig (>=0.02); anything quieter is not a relay.
        lone = events[0]
        return ([lone], [], None) if lone["peak"] >= 0.02 else ([], events, None)
    ratios = [(peaks[i + 1] / max(peaks[i], 1e-12), peaks[i], peaks[i + 1])
              for i in range(len(peaks) - 1)]
    r, lo, hi = max(ratios)
    if r < 4.0:                       # no clear bimodality - keep everything
        return events, [], None
    thr = (lo * hi) ** 0.5
    loud = [e for e in events if e["peak"] > thr]
    quiet = [e for e in events if e["peak"] <= thr]
    return loud, quiet, dict(threshold=thr, ratio=r, lo=lo, hi=hi)


def tx(sock, cid, data):
    sock.send(struct.pack("=IB3x8s", cid, len(data), bytes(data).ljust(8, b"\0")))


# ---------------------------------------------------------------- reference
def build_reference(wav=None, js=None):
    """Relay signatures (spectral centroid per d3) from an earlier trial."""
    if wav is None:
        c = sorted(glob.glob(os.path.join(LOGS, "*ab_nib1.wav")))
        if not c:
            return None
        wav = c[-1]
        js = wav.replace(".wav", ".json")
    if not (os.path.exists(wav) and os.path.exists(js)):
        return None
    ab = json.load(open(js))
    x, rate = read_wav(wav)
    det = detect(wav, k=8.0)
    off = ab.get("best_offset", 0.0)
    ref = {}
    ev, _, _ = split_classes(det["events"])
    for e in ev:
        sp = spectrum(x, rate, e["t"])
        if sp is None:
            continue
        f = features(*sp)
        if f is None:
            continue
        al = e["t"] - off
        near = min(ab["strobes"], key=lambda s: abs(s["t"] - al))
        if abs(near["t"] - al) < 0.06 and near["d3"] is not None:
            ref.setdefault(near["d3"], []).append(f[0])
    return {k: dict(mean=float(np.mean(v)), sd=float(np.std(v)), n=len(v))
            for k, v in ref.items()}


# -------------------------------------------------------------------- trial
def one_trial(a, stamp):
    canlog = os.path.join(LOGS, "%s_q_nib%d.log" % (stamp, a.nibble))
    wav = os.path.join(LOGS, "%s_q_nib%d.wav" % (stamp, a.nibble))
    cap = subprocess.Popen(["candump", "-ta", a.iface],
                           stdout=open(canlog, "w"), stderr=subprocess.DEVNULL)
    rec = subprocess.Popen(["parecord", "--channels=1", "--rate=48000",
                            "--format=s16le", "--file-format=wav", wav],
                           stderr=subprocess.DEVNULL)
    time.sleep(1.0)
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

    idle(a.settle)
    for _ in range(a.presses):
        press(a.hold)
        idle(a.gap)
    idle(1.2)
    time.sleep(0.4)
    cap.send_signal(signal.SIGINT); cap.wait(timeout=5)
    rec.terminate()
    try:
        rec.wait(timeout=5)
    except subprocess.TimeoutExpired:
        rec.kill()
    return canlog, wav


def parse_can(canlog):
    frames, strobes = [], []
    with open(canlog) as fh:
        for ln in fh:
            m = LINE.match(ln.strip())
            if not m:
                continue
            t, _, cid, _, data = m.groups()
            if int(cid, 16) != 0x03A:
                continue
            d = [int(x, 16) for x in data.split()]
            frames.append((float(t), d))
            if len(d) > 1 and d[1] & 0x40:
                strobes.append((float(t), d[3] if len(d) > 3 else None))
    return frames, strobes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="can1")
    ap.add_argument("--nibble", type=int, required=True)
    ap.add_argument("--presses", type=int, default=3)
    ap.add_argument("--hold", type=float, default=0.4)
    ap.add_argument("--gap", type=float, default=1.8)
    ap.add_argument("--settle", type=float, default=2.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--lead", type=float, default=2.0)
    a = ap.parse_args()
    os.makedirs(LOGS, exist_ok=True)

    ref = build_reference()
    print("=== reference relay signatures (from an earlier trial) ===")
    if ref:
        for k, v in sorted(ref.items()):
            print("   d3=%s  centroid %.1f Hz (sd %.1f, n=%d)"
                  % (hex(k), v["mean"], v["sd"], v["n"]))
    else:
        print("   (none available - clicks will be reported unclassified)")

    dur = a.settle + a.presses * (a.hold + a.gap) + 2.6
    print("\n*** BE QUIET NOW - recording for ~%.0f s ***" % dur)
    time.sleep(a.lead)

    for attempt in range(1, a.retries + 1):
        stamp = time.strftime("%Y%m%dT%H%M%S")
        canlog, wav = one_trial(a, stamp)
        frames, strobes = parse_can(canlog)
        det = detect(wav, k=3.0)     # low k: find weak events, then split below
        loud, quiet, split = split_classes(det["events"])

        bad = det.get("degenerate") or len(loud) > 3 * max(len(strobes), 1)
        if bad and attempt < a.retries:
            print("\n[attempt %d] CONTAMINATED (degenerate=%s, loud=%d, strobes=%d)"
                  " - retrying, please stay quiet"
                  % (attempt, det.get("degenerate"), len(loud), len(strobes)))
            time.sleep(1.5)
            continue

        print("\n=== RESULT (attempt %d) ===" % attempt)
        print("CAN : %d 0x3A frames, %d execute strobe(s); d3 seen: %s"
              % (len(frames), len(strobes),
                 sorted({hex(v) for _, v in strobes if v is not None}) or "-"))
        t0 = frames[0][0] if frames else 0.0
        for t, v in strobes:
            print("      strobe t=%7.3f  d3=%s" % (t - t0, hex(v) if v is not None else "?"))

        if bad:
            print("AUDIO: REJECTED after %d attempts (room not quiet enough)."
                  % a.retries)
            print("       No acoustic conclusion. CAN result above still stands.")
            return

        print("AUDIO: %d actuation click(s)%s"
              % (len(loud),
                 ("; class split at peak %.5f (%.0fx gap)"
                  % (split["threshold"], split["ratio"])) if split else ""))
        if not loud:
            print("\n  ⇒ VALID NEGATIVE: audio is clean but NO relay actuated.")
            print("    For this command the BCM emits the CAN command WITHOUT")
            print("    driving a lock actuator - a real result, not a failure.")
        else:
            x, rate = read_wav(wav)
            for e in loud:
                sp = spectrum(x, rate, e["t"])
                f = features(*sp) if sp else None
                cen = f[0] if f else float("nan")
                lab, dist = "-", None
                if ref and f:
                    lab, dist = min(((hex(k), abs(cen - v["mean"]))
                                     for k, v in ref.items()), key=lambda z: z[1])
                print("      click t=%7.3f  snr=%6.0f  centroid %7.1f Hz"
                      "   -> matches %s (%.0f Hz away)"
                      % (e["t"], e["snr"], cen, lab, dist if dist is not None else -1))
            print("\n  ⇒ %d actuation(s) detected and identified above." % len(loud))
        print("\n  can: %s\n  wav: %s" % (canlog, wav))
        return


if __name__ == "__main__":
    main()
