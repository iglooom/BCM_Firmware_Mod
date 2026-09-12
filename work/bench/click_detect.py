#!/usr/bin/env python3
"""Acoustic relay-click detector, time-aligned with a CAN capture.

With no DDM/PDM on the bench, the BCM drives the door-lock motors from its own
hard-wired outputs, so every actuation is an audible relay click.  That click is
PHYSICAL GROUND TRUTH: "the relay fired" is the actuation itself, whereas
"0x3A d3 went to 01" is only a claim about a byte.  This turns the click into a
timestamped channel that can be correlated against candump.

Why this is sound despite being "just a laptop mic": we are not doing audio
forensics.  We only need the ONSET TIME of a loud, sharp, wideband transient
against a quiet background, to a tolerance (~10 ms) far coarser than the audio
frame rate.  A relay click is close to ideal for that.

Method
  * record mono 48 kHz WAV via `parecord` (PipeWire), started and stopped by us
  * detect onsets on a short-window energy envelope in a HIGH-PASS band, so
    fan/hum/voice (low frequency, slowly varying) do not trigger
  * adaptive threshold = median + K * MAD of the envelope (robust to outliers;
    a plain mean/std is dragged up by the very clicks we are hunting)
  * refractory period so one physical click is one event, not a burst

⚠ The clock: both the WAV and candump are stamped from the same host clock, but
the audio stream starts when the recorder opens the device.  We therefore do not
assume t=0 alignment - `bench_ab.py` aligns the two streams by CROSS-CORRELATING
the click train against the CAN strobe train and REPORTS the fitted offset.  An
offset that is implausibly large is a red flag, not something to silently absorb.

Usage
  click_detect.py record  --secs 20 --out /tmp/x.wav
  click_detect.py detect  /tmp/x.wav [--k 8] [--json out.json]
  click_detect.py level   --secs 3          # mic sanity / gain check
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import time
import wave

import numpy as np

RATE = 48000


# --------------------------------------------------------------- recording
def record(path, secs, source=None):
    cmd = ["parecord", "--channels=1", "--rate=%d" % RATE,
           "--format=s16le", "--file-format=wav"]
    if source:
        cmd += ["--device=%s" % source]
    cmd += [path]
    p = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
    t0 = time.time()
    time.sleep(secs)
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
    return t0


def read_wav(path):
    with wave.open(path, "rb") as w:
        n, rate, ch = w.getnframes(), w.getframerate(), w.getnchannels()
        raw = w.readframes(n)
    x = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    if ch > 1:
        x = x.reshape(-1, ch).mean(axis=1)
    return x, rate


# --------------------------------------------------------------- detection
def highpass(x, rate, fc=1500.0):
    """One-pole high-pass: kills fan rumble / hum / voice fundamentals."""
    a = np.exp(-2.0 * np.pi * fc / rate)
    y = np.empty_like(x)
    prev_x = 0.0
    prev_y = 0.0
    # vectorised single-pole is awkward; lfilter-free loop over a decimated
    # signal is fast enough for <60 s clips, but do it in numpy via cumulative
    # trick: fall back to a simple difference + smoothing, which is adequate
    # for onset detection and needs no scipy.
    y = np.diff(x, prepend=x[0])          # crude but effective HP for transients
    return y


def envelope(x, rate, win_ms=5.0):
    w = max(1, int(rate * win_ms / 1000.0))
    p = x * x
    c = np.cumsum(np.insert(p, 0, 0.0))
    e = (c[w:] - c[:-w]) / w
    return np.sqrt(e), w


def detect(path, k=8.0, refractory_ms=120.0, win_ms=5.0):
    x, rate = read_wav(path)
    hp = highpass(x, rate)
    env, w = envelope(hp, rate, win_ms)
    med = float(np.median(env))
    mad = float(np.median(np.abs(env - med)))
    # ⚠ MAD COLLAPSE.  If more than half the envelope samples are (near) equal -
    # digital silence, a muted source, or heavy noise-gating - then median and
    # MAD are both ~0 and `median + k*MAD` collapses to ~0, so EVERY sample is
    # "above threshold" and the detector reports dozens of events with absurd
    # SNRs (observed: mad=1e-12, 74 events, snr~1e8).  That is a broken
    # instrument, not a loud recording.  Fall back to a scale derived from the
    # signal itself and flag the condition so the caller can refuse the trial.
    degenerate = mad <= 1e-9
    if degenerate:
        mad = float(np.std(env)) or float(env.max()) or 1e-9
    thr = med + k * mad
    # absolute floor: a relay click is a large transient; never accept a
    # threshold below a fraction of the envelope's own peak.
    floor = 0.02 * float(env.max()) if env.size else 0.0
    thr = max(thr, floor)
    above = env > thr
    idx = np.flatnonzero(above[1:] & ~above[:-1]) + 1
    refr = int(rate * refractory_ms / 1000.0)
    scale = med if med > 1e-9 else (float(np.median(env[env > 0])) if np.any(env > 0) else 1e-9)
    events, last = [], -10 ** 9
    for i in idx:
        if i - last < refr:
            continue
        last = i
        seg = env[i:i + int(rate * 0.05)]
        events.append(dict(t=round(i / rate, 4),
                           peak=round(float(seg.max()) if seg.size else 0.0, 6),
                           snr=round(float((seg.max() if seg.size else 0) / scale), 1)))
    return dict(path=path, rate=rate, duration=round(len(x) / rate, 3),
                median=med, mad=mad, threshold=thr, k=k,
                degenerate=bool(degenerate),
                n_events=len(events), events=events)


def level(secs, source=None):
    """Mic sanity check: is anything arriving, and is the gain sane?"""
    tmp = "/tmp/_lvl.wav"
    record(tmp, secs, source)
    x, rate = read_wav(tmp)
    if x.size == 0:
        print("NO AUDIO CAPTURED - check the source/permissions")
        return
    rms = float(np.sqrt((x * x).mean()))
    pk = float(np.abs(x).max())
    print("duration   : %.2f s @ %d Hz" % (len(x) / rate, rate))
    print("RMS        : %.5f  (%.1f dBFS)" % (rms, 20 * np.log10(max(rms, 1e-9))))
    print("peak       : %.5f  (%.1f dBFS)" % (pk, 20 * np.log10(max(pk, 1e-9))))
    clipped = int((np.abs(x) > 0.99).sum())
    print("clipped    : %d samples %s" % (clipped, "<-- REDUCE GAIN" if clipped else ""))
    if pk < 0.01:
        print("VERDICT    : very quiet - raise mic volume or move the mic closer")
    elif clipped:
        print("VERDICT    : clipping - lower the mic volume")
    else:
        print("VERDICT    : level looks usable")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["record", "detect", "level"])
    ap.add_argument("wav", nargs="?")
    ap.add_argument("--secs", type=float, default=20.0)
    ap.add_argument("--out", default="/tmp/bench_audio.wav")
    ap.add_argument("--source")
    ap.add_argument("--k", type=float, default=8.0)
    ap.add_argument("--json")
    a = ap.parse_args()
    if a.mode == "record":
        t0 = record(a.out, a.secs, a.source)
        print(json.dumps(dict(wav=a.out, t0=t0, secs=a.secs)))
    elif a.mode == "level":
        level(a.secs, a.source)
    else:
        res = detect(a.wav or a.out, a.k)
        if a.json:
            with open(a.json, "w") as fh:
                json.dump(res, fh, indent=1)
        print("events: %d  (threshold %.6f = median %.6f + %.0f*MAD %.6f)"
              % (res["n_events"], res["threshold"], res["median"], res["k"], res["mad"]))
        for e in res["events"]:
            print("   t=%8.3f s  peak=%.5f  snr=%.1f" % (e["t"], e["peak"], e["snr"]))


if __name__ == "__main__":
    main()
