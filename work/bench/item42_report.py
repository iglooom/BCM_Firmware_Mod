#!/usr/bin/env python3
"""Item 42 analysis: which frame bytes change after the nibble-3 stimulus, and
for how long?

Compares a BASELINE window (before the press) against the window AFTER it, for
every (CAN id, byte) on both buses, and measures how long each change persists.

The prediction under test (from static script 250): the changed set should be
    HS 0x380 d4 | MS 0x1A8 d0 | MS 0x1B0 d2 | MS 0x290 d0 | MS 0x370 d4
and the change should be TIMED (it reverts), with duration = DAT_4000588F * 50
ticks - which lets us read DAT_4000588F off the wire.

The verdict is explicit about all four outcomes: predicted-and-timed,
predicted-but-permanent, unpredicted bytes (=> 250 is wrong), or no change at
all (=> the stimulus does not reach the feature).

usage: item42_report.py <hs.log> <ms.log> <t_press> <t_after>
"""
import re
import sys
from collections import defaultdict

LINE = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-F]{3})\s+\[(\d+)\]\s+(.*)")

PREDICTED = {
    ("can0", 0x380, 4), ("can1", 0x1A8, 0), ("can1", 0x1B0, 2),
    ("can1", 0x290, 0), ("can1", 0x370, 4),
}


def load(path):
    out = []
    with open(path) as fh:
        for ln in fh:
            m = LINE.match(ln.strip())
            if not m:
                continue
            t, iface, cid, _, data = m.groups()
            out.append((float(t), iface, int(cid, 16),
                        [int(x, 16) for x in data.split()]))
    return out


def main():
    hs, ms, t_press, t_after = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
    frames = load(hs) + load(ms)
    frames.sort()
    if not frames:
        print("no frames")
        return

    # ⚠ THREE ARTIFACTS that made the first version of this diff useless.  Each
    # produced "changed" bytes that have nothing to do with the stimulus, and
    # together they buried the real signal under 25 false positives:
    #
    #  1. SELF-TRANSMITTED frames.  0x100 is OUR stimulus; naturally its bytes
    #     "change".  Exclude ids we transmit.
    #  2. COUNTERS / free-running values.  A 4 s baseline cannot observe every
    #     value of a rolling counter, so any later value looks new.  Require the
    #     baseline to be STABLE (few distinct values) before judging a change.
    #  3. NON-REVERTING changes.  A byte that differs for the entire post-window
    #     is free-running, not a timed feature.  Require a RETURN to a baseline
    #     value - that is what makes a change "timed" and lets us measure it.
    SELF_TX = {0x100}
    MAX_BASE_VALUES = 3          # a stable signal takes very few values

    base = defaultdict(list)
    for t, ifc, cid, d in frames:
        if cid in SELF_TX:
            continue
        if t < t_press:
            for i, b in enumerate(d):
                base[(ifc, cid, i)].append(b)

    stable = {k: set(v) for k, v in base.items()
              if len(set(v)) <= MAX_BASE_VALUES and len(v) >= 5}
    print("baseline: %d byte-channels seen, %d stable enough to test"
          % (len(base), len(stable)))

    # post-stimulus trace per channel
    post = defaultdict(list)
    for t, ifc, cid, d in frames:
        if cid in SELF_TX or t < t_press:
            continue
        for i, b in enumerate(d):
            k = (ifc, cid, i)
            if k in stable:
                post[k].append((t, b))

    t_end = frames[-1][0]
    changed = {}
    for k, seq in post.items():
        bvals = stable[k]
        dev = [(t, b) for t, b in seq if b not in bvals]
        if not dev:
            continue
        first, last = dev[0][0], dev[-1][0]
        # did it come back to a baseline value AFTER the last deviation?
        reverted = any(t > last and b in bvals for t, b in seq) or (t_end - last) > 1.0
        changed[k] = dict(first=first, last=last, dur=last - first,
                          vals=sorted({b for _, b in dev}),
                          base=sorted(bvals), reverted=reverted,
                          n_dev=len(dev))

    print("\n=== stable bytes that deviated after the nibble-3 press ===")
    if not changed:
        print("   NONE.")
    for k, v in sorted(changed.items(), key=lambda x: x[1]["first"]):
        ifc, cid, i = k
        tag = "  <== PREDICTED" if k in PREDICTED else ""
        print("   %-5s 0x%03X d%-2d  %s -> %s   t+%.2f..%.2f (%.2f s) %s%s"
              % (ifc, cid, i, [hex(x) for x in v["base"]],
                 [hex(x) for x in v["vals"]],
                 v["first"] - t_press, v["last"] - t_press, v["dur"],
                 "REVERTED" if v["reverted"] else "PERSISTS", tag))

    hit = set(changed) & PREDICTED
    miss = PREDICTED - set(changed)
    extra = set(changed) - PREDICTED
    print("\n=== verdict on the static prediction (script 250) ===")
    print("   predicted bytes that changed : %d/%d %s"
          % (len(hit), len(PREDICTED),
             sorted("%s 0x%03X d%d" % (a, b, c) for a, b, c in hit)))
    print("   predicted, did NOT change    : %s"
          % (sorted("%s 0x%03X d%d" % (a, b, c) for a, b, c in miss) or "none"))
    print("   changed, NOT predicted       : %s"
          % (sorted("%s 0x%03X d%d" % (a, b, c) for a, b, c in extra) or "none"))
    print("\n   NOTE: 0x03A d1/d3 are the command frame itself (strobe + command)")
    print("   and are EXPECTED to change - they are not evidence about 0x40002E44.")
    real_extra = {k for k in extra if k[1] != 0x03A}
    if hit:
        print("\n   ⇒ PREDICTION HELD for %d byte(s)." % len(hit))
        for k in sorted(hit):
            v = changed[k]
            if v["reverted"]:
                print("     timed: %s 0x%03X d%d lasted %.2f s"
                      " => DAT_4000588F ~= %.1f (1 tick = 10 ms)"
                      % (k[0], k[1], k[2], v["dur"], v["dur"] / 0.5))
    elif real_extra:
        print("\n   ⇒ PREDICTION FAILED: real changes occurred, but not at the")
        print("     predicted bytes. Script 250's cell->frame mapping for")
        print("     0x40002E44 needs redoing.")
    else:
        print("\n   ⇒ NO CHANGE outside the command frame itself. The feature")
        print("     driven by nibble 3 emits NOTHING observable on either bus")
        print("     beyond 0x3A - consistent with the acoustic result that it")
        print("     actuates no relay. Either it needs conditions the bench")
        print("     cannot provide (ignition, DDM/PDM), or 0x40002E44 is simply")
        print("     not written on this path.")


if __name__ == "__main__":
    main()
