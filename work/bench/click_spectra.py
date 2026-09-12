#!/usr/bin/env python3
"""Spectral fingerprinting of relay clicks - are they DIFFERENT relays?

User observation on the bench: within one LOCK press the BCM emits a triplet of
clicks, and "the first two sound different in pitch from the last" - suggesting
two physically distinct relays (e.g. a LOCK relay and an UNLOCK relay), not one
relay firing three times.

That is a falsifiable claim, so measure it rather than trust an ear (or mine).

Method
  * take each detected onset, cut a short window, and compute its magnitude
    spectrum (Hann-windowed rFFT, no scipy needed)
  * summarise each click by its spectral CENTROID and by a coarse band profile
  * CLUSTER the clicks on those features and compare the clustering against the
    CAN ground truth: each click's nearest execute strobe carries d3, so we
    already KNOW which clicks were lock (d3=01) and which were unlock (d3=02)
  * the acceptance test is therefore not "do the spectra differ" (any two noisy
    windows differ) but: DOES THE SPECTRAL SPLIT AGREE WITH THE d3 LABEL?

Controls
  * WITHIN-class vs BETWEEN-class distance: if between-class separation is not
    larger than within-class scatter, there is no real difference (this is the
    rule-9 guard - two groups always differ a bit; the question is whether they
    differ MORE than members of the same group do).
  * a label-shuffle: recompute the separation with d3 labels randomly permuted,
    200 times.  The true split must beat that null.

usage: click_spectra.py <wav> <ab_json>
"""
import json
import sys

import numpy as np

from click_detect import detect, read_wav


def spectrum(x, rate, t, win=0.030):
    i = int(t * rate)
    n = int(win * rate)
    seg = x[i:i + n]
    if seg.size < n // 2:
        return None
    seg = seg * np.hanning(seg.size)
    mag = np.abs(np.fft.rfft(seg, n=4096))
    freq = np.fft.rfftfreq(4096, 1.0 / rate)
    return freq, mag


def features(freq, mag, fmin=300.0, fmax=12000.0):
    band = (freq >= fmin) & (freq <= fmax)
    f, m = freq[band], mag[band]
    if m.sum() <= 0:
        return None
    centroid = float((f * m).sum() / m.sum())
    # coarse octave-ish band profile, normalised (shape, not loudness)
    edges = [300, 600, 1200, 2400, 4800, 9600, 12000]
    prof = []
    for a, b in zip(edges[:-1], edges[1:]):
        sel = (f >= a) & (f < b)
        prof.append(float(m[sel].sum()))
    prof = np.array(prof)
    prof = prof / (prof.sum() or 1.0)
    # spectral rolloff (85% energy point)
    c = np.cumsum(m)
    roll = float(f[np.searchsorted(c, 0.85 * c[-1])]) if c[-1] > 0 else 0.0
    return centroid, roll, prof


def main():
    wav, abjson = sys.argv[1], sys.argv[2]
    ab = json.load(open(abjson))
    x, rate = read_wav(wav)
    det = detect(wav, k=8.0)
    off = ab["best_offset"]
    strobes = ab["strobes"]

    rows = []
    for e in det["events"]:
        if e["snr"] < 100:                      # loud class only
            continue
        sp = spectrum(x, rate, e["t"])
        if sp is None:
            continue
        f = features(*sp)
        if f is None:
            continue
        centroid, roll, prof = f
        # CAN ground truth: nearest strobe after removing the fitted offset
        al = e["t"] - off
        near = min(strobes, key=lambda s: abs(s["t"] - al)) if strobes else None
        dt = abs(near["t"] - al) if near else 9e9
        rows.append(dict(t=e["t"], aligned=round(al, 3), snr=e["snr"],
                         centroid=round(centroid, 1), rolloff=round(roll, 1),
                         prof=[round(p, 4) for p in prof],
                         d3=(near["d3"] if near and dt < 0.06 else None),
                         dt_ms=round(dt * 1000, 1)))

    print("click | aligned |   snr |  centroid |  rolloff | d3   | dt(ms)")
    print("------+---------+-------+-----------+----------+------+-------")
    for i, r in enumerate(rows):
        print("%5d | %7.3f | %5.0f | %9.1f | %8.1f | %-4s | %6.1f"
              % (i, r["aligned"], r["snr"], r["centroid"], r["rolloff"],
                 hex(r["d3"]) if r["d3"] is not None else "-", r["dt_ms"]))

    lab = {}
    for r in rows:
        if r["d3"] is not None:
            lab.setdefault(r["d3"], []).append(r)
    print("\n=== grouped by the CAN d3 label ===")
    for k, v in sorted(lab.items()):
        cs = [r["centroid"] for r in v]
        print("  d3=%s  n=%d  centroid mean=%.1f Hz  sd=%.1f  range=[%.1f, %.1f]"
              % (hex(k), len(v), np.mean(cs), np.std(cs), min(cs), max(cs)))

    if len(lab) < 2:
        print("\nonly one d3 class present - run a trial containing both to compare")
        return

    # ---- separation test --------------------------------------------------
    def profmat(v):
        return np.array([r["prof"] for r in v])

    keys = sorted(lab)
    A, B = profmat(lab[keys[0]]), profmat(lab[keys[1]])

    def within(M):
        if len(M) < 2:
            return 0.0
        return float(np.mean([np.linalg.norm(M[i] - M[j])
                              for i in range(len(M)) for j in range(i + 1, len(M))]))

    def between(A, B):
        return float(np.mean([np.linalg.norm(a - b) for a in A for b in B]))

    wa, wb, bt = within(A), within(B), between(A, B)
    print("\n=== separation on the normalised band profile ===")
    print("  within d3=%s : %.4f" % (hex(keys[0]), wa))
    print("  within d3=%s : %.4f" % (hex(keys[1]), wb))
    print("  between      : %.4f" % bt)
    ratio = bt / (max((wa + wb) / 2.0, 1e-9))
    print("  between/within ratio : %.2f" % ratio)

    # ---- label-shuffle null ----------------------------------------------
    allr = lab[keys[0]] + lab[keys[1]]
    n0 = len(lab[keys[0]])
    M = np.array([r["prof"] for r in allr])
    rng = np.random.default_rng(0)
    null = []
    for _ in range(200):
        idx = rng.permutation(len(M))
        A2, B2 = M[idx[:n0]], M[idx[n0:]]
        w = (within(A2) + within(B2)) / 2.0
        null.append(between(A2, B2) / max(w, 1e-9))
    null = np.array(null)
    p = float((null >= ratio).mean())
    print("  shuffled-label null  : mean %.2f, 95th pct %.2f" % (null.mean(), np.percentile(null, 95)))
    print("  p(shuffle >= observed) = %.3f" % p)
    if p < 0.05:
        print("\n  ⇒ The spectral split AGREES with the d3 label: the clicks are")
        print("    acoustically distinct by command - consistent with TWO RELAYS.")
    else:
        print("\n  ⇒ NOT SIGNIFICANT: the spectra do not separate by d3 any better")
        print("    than random labels would. Do not claim two relays from this.")


if __name__ == "__main__":
    main()
