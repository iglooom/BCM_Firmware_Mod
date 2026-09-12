#!/usr/bin/env python3
"""DIFFERENTIAL RAM SCAN: which cells distinguish REMOTE-START-RUNNING from QUIET?

vehicle_session_1.md left the real question open: power_mode does NOT change
during a real remote start (constant 0x04 on peek, 0x7D on the wire), and
FUN_000ADADA's hold timer never ticks -- so the cells this project has been
watching are probably not on the live path.  This finds the ones that are.

DESIGN -- built against the defects bench_session_3.md Sec.6.1 documented:

  * MULTIPLE PASSES PER CONDITION.  A cell sampled once per pass has
    quantifiable blindness; a cell active only part of the time will be missed.
    We do N passes per condition and keep the full value SET per cell.

  * NULL ON BOTH SIDES (rule 29/40).  quiet BEFORE and quiet AFTER, not just
    before -- a press-armed-then-free-running mechanism is invisible to a
    before-only control.

  * FREE-RUNNING REJECTION (rule 9).  A cell that takes many values while
    quiet will always show "a new value" when active.  A candidate must be
    CONSTANT across every quiet pass AND take a value never seen quiet.

  * ERR IS NOT A VALUE.  A transport hiccup folded into the value set becomes
    a fake discovery.  ERR is recorded separately and excludes the cell.

  * ONE CLOCK.  This script drives everything, so quiet/active timestamps are
    comparable -- the previous run used two independently-started processes
    and no cross-log timing claim was supportable.

USAGE
    # 1. car quiet/locked, engine off
    python3 310_rs_diff.py quiet   --passes 4 --tag pre
    # 2. operator starts the remote start, engine running
    python3 310_rs_diff.py active  --passes 4
    # 3. operator stops it, car quiet again
    python3 310_rs_diff.py quiet   --passes 4 --tag post
    # 4. verdict
    python3 310_rs_diff.py report

Scan range defaults to the remote-start state block neighbourhood, which is
where the evidence points.  --range to widen.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bench"))
from peeklib import Peeker  # noqa: E402

OUT = os.path.join(HERE, "logs", "rs_diff.json")

# The 0x400095EC state block (confirmed base, vehicle_session_1.md Sec.1.2)
# plus the named cells this project already knows.
DEFAULT_LO, DEFAULT_HI = 0x400095C0, 0x400096C0
EXTRA = [0x40001D84, 0x40002DA0, 0x40008D2C, 0x40008D74, 0x40003EB4,
         0x40001E60, 0x40001E78]


def cells(lo, hi):
    return list(range(lo, hi, 4)) + EXTRA


def collect(cond, passes, lo, hi, tag):
    addrs = cells(lo, hi)
    print("=" * 72)
    print("COLLECT  condition=%s  passes=%d  cells=%d" % (cond, passes, len(addrs)))
    print("  range 0x%08X..0x%08X + %d named" % (lo, hi, len(EXTRA)))
    print("=" * 72)
    data = {}
    errs = {}
    t0 = time.time()
    with Peeker() as p:
        p.wake()
        for k in range(passes):
            n_err = 0
            for a in addrs:
                try:
                    v = p.read32(a)
                    key = "%08X" % v
                except Exception:
                    key = None
                    n_err += 1
                if key is None:
                    errs.setdefault("%08X" % a, 0)
                    errs["%08X" % a] += 1
                else:
                    data.setdefault("%08X" % a, []).append(key)
            print("   pass %d/%d done (%.1fs, %d errors)"
                  % (k + 1, passes, time.time() - t0, n_err))
            sys.stdout.flush()

    store = {}
    if os.path.exists(OUT):
        store = json.load(open(OUT))
    key = cond if not tag else "%s_%s" % (cond, tag)
    store[key] = {"values": data, "errors": errs, "passes": passes,
                  "lo": lo, "hi": hi, "t": time.time()}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(store, open(OUT, "w"))
    print("\n  saved condition '%s' (%d cells)" % (key, len(data)))


def report():
    store = json.load(open(OUT))
    quiet_keys = [k for k in store if k.startswith("quiet")]
    act = store.get("active")
    print("=" * 72)
    print("REPORT")
    print("=" * 72)
    print("  quiet conditions: %s" % ", ".join(quiet_keys))
    print("  active present  : %s" % ("yes" if act else "NO -- cannot report"))
    if not act or not quiet_keys:
        print("\n  Need at least one quiet set and the active set.")
        return 1
    if len(quiet_keys) < 2:
        print("\n  ⚠ Only ONE quiet condition.  Rule 29/40 wants quiet BEFORE")
        print("    and AFTER; a one-sided null is weaker.  Proceeding, flagged.")

    # union of quiet values per cell
    qv = {}
    qerr = set()
    for k in quiet_keys:
        for a, vals in store[k]["values"].items():
            qv.setdefault(a, set()).update(vals)
        qerr |= set(store[k]["errors"].keys())

    cands, freerun, errored = [], [], []
    for a, vals in act["values"].items():
        av = set(vals)
        if a in qerr or a in act["errors"]:
            errored.append(a)
            continue
        q = qv.get(a)
        if q is None:
            continue
        if len(q) > 1:
            freerun.append((a, len(q), len(av)))
            continue                      # free-running: rejected (rule 9)
        new = av - q
        if new:
            # must RECUR, not appear once
            recur = [v for v in new if vals.count(v) > 1]
            cands.append((a, sorted(q)[0], sorted(new), bool(recur),
                          len(vals)))

    print("\n  cells scanned      : %d" % len(act["values"]))
    print("  rejected free-run  : %d" % len(freerun))
    print("  rejected errored   : %d" % len(errored))
    print("  CANDIDATES         : %d" % len(cands))
    print()
    if not cands:
        print("  No cell is constant-while-quiet and different-while-active.")
        print("  ⚠ With %d passes this is a claim about cells whose active"
              % act["passes"])
        print("    state persists long enough to be sampled -- a brief")
        print("    transient would be missed (rule 40).")
        return 0

    print("  %-10s %-10s %-28s %s" % ("cell", "quiet", "active-only values",
                                      "recurring?"))
    for a, q, new, recur, n in sorted(cands, key=lambda c: -int(c[3])):
        print("  0x%-8s %-10s %-28s %s"
              % (a, q, " ".join(new[:3]), "YES" if recur else "once only"))
    print()
    print("  'recurring' = seen in more than one active sample; a once-only")
    print("  value is weaker evidence and may be a sampling artifact.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["quiet", "active", "report"])
    ap.add_argument("--passes", type=int, default=4)
    ap.add_argument("--tag", default="")
    ap.add_argument("--range", default="")
    a = ap.parse_args()
    lo, hi = DEFAULT_LO, DEFAULT_HI
    if a.range:
        s, e = a.range.split("-")
        lo, hi = int(s, 16), int(e, 16)
    if a.cmd == "report":
        return report()
    return collect(a.cmd, a.passes, lo, hi, a.tag)


if __name__ == "__main__":
    sys.exit(main())
