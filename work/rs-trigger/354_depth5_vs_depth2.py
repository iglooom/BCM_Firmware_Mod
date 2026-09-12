#!/usr/bin/env python3
"""354 -- DEPTH 5 vs DEPTH 2: does the ANNOUNCE byte make the chain advance?

THE EXPERIMENT
Both depths write the identical command code 0x1808 to 0x40002DA2.  They differ
in ONE byte: what they store to the Volcano dirty-flag 0x40003F53.

    depth 2 -> 0x01   = bit index 7, read by NO consumer   (the broken arm)
    depth 5 -> 0xFF   = all bits, incl. mask 0x20 which the RS consumer tests

So this is a controlled A/B with a single varied factor.  If depth 5 advances
the chain and depth 2 does not, the announce byte is the mechanism -- and the
command code is exonerated, because it is identical in both arms.

THE CHAIN WE WATCH (verified statically in Sec.10):
    0x40003F53  announce byte            <- we write this
    0x0AEEDA    test-and-clear (n=2, mask 0x20)
    0x4000968B  written by that consumer
    0x400095E1  copied from it            <- the flag Sec.7 found
    0x0ADA24    reads it, compares == 1
    0x0ADA3E    sets bit 27 of 0x40009680

BASELINE DISCIPLINE (rule 52): every cell is sampled BEFORE each arm, and the
arms are run in BOTH orders (2-then-5 and 5-then-2) so an effect cannot be an
artifact of ordering or of leftover state.

INSTRUMENT NOTE (rule 26 / Sec.9.2): reading N cells per loop makes the loop
period N x the UDS round trip.  The per-arm watch here polls ONE decisive cell
(the 0x400095E1 flag word) to keep resolution high, and reads the rest only at
the start and end of each arm.

CONTROL (rule 27): peek itself is proven live by a known-truth flash read
before anything is fired.  If that fails, nothing below means anything.

SAFETY: depth 5 synthesises a real remote-start command.  On the BENCH this is
safe (no engine).  Do NOT run this on a vehicle without PARK + brake + open air.
"""
import sys
import os
import time
import argparse
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "work", "bench"))

from peeklib import Peeker  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "did", os.path.join(ROOT, "work", "bench", "293_did_read.py"))
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
read_did = _m.read_did

ANNOUNCE_W = 0x40003F50   # announce byte 0x40003F53 = LSB of this word
CODE_W = 0x40002DA0       # command code 0x40002DA2 = low halfword
CONSUMER_W = 0x40009688   # 0x4000968B = LSB
FLAG_W = 0x400095E0       # 0x400095E1 = byte +1 -> bits 16..23
GATE = 0x40009680         # bit 27
SUBSTATE = 0x4000967C

DID = {2: 0xDE16, 5: 0xDE4A}
KNOWN_TRUTH_ADDR = 0x000DE278
KNOWN_TRUTH_VAL = 0x70E8E000


def wide(p):
    return {
        "announce": p.read32(ANNOUNCE_W) & 0xFF,
        "code": p.read32(CODE_W) & 0xFFFF,
        "consumer": p.read32(CONSUMER_W) & 0xFF,
        "flag": (p.read32(FLAG_W) >> 16) & 0xFF,
        "gate27": (p.read32(GATE) >> 27) & 1,
        "sub": (p.read32(SUBSTATE) >> 26) & 3,
    }


def show(tag, s):
    print("    %-9s announce=0x%02X code=0x%04X consumer=0x%02X "
          "flag=0x%02X bit27=%d sub=%d"
          % (tag, s["announce"], s["code"], s["consumer"], s["flag"],
             s["gate27"], s["sub"]))


def run_arm(p, depth, watch_s):
    print("\n" + "-" * 70)
    print("  ARM: depth %d  (DID 0x%04X)  announce=%s"
          % (depth, DID[depth], "0x01 BROKEN" if depth == 2 else "0xFF"))
    print("-" * 70)

    before = wide(p)
    show("before", before)

    ok, val = read_did(p, DID[depth])
    print("    fired -> %s" % (bytes(val).hex().upper() if ok else val))

    # poll ONE cell fast: the flag word carries 0x400095E1
    t0 = time.time()
    flag_vals = set()
    bit27_hits = 0
    while time.time() - t0 < watch_s:
        fw = p.read32(FLAG_W)
        flag_vals.add((fw >> 16) & 0xFF)
        if (p.read32(GATE) >> 27) & 1:
            bit27_hits += 1
        time.sleep(0.005)

    after = wide(p)
    show("after", after)
    print("    flag byte values seen during watch: %s"
          % " ".join("0x%02X" % v for v in sorted(flag_vals)))
    print("    bit 27 high in %d samples" % bit27_hits)

    advanced = (after["consumer"] != before["consumer"]
                or after["flag"] != before["flag"]
                or bit27_hits > 0
                or (flag_vals - {before["flag"]}))
    print("    => chain %s" % ("ADVANCED" if advanced else "did not advance"))
    return {"before": before, "after": after, "flags": flag_vals,
            "bit27": bit27_hits, "advanced": bool(advanced)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", type=float, default=3.0)
    ap.add_argument("--order", default="2,5",
                    help="arm order, e.g. '2,5' or '5,2'")
    ap.add_argument("--both-orders", action="store_true",
                    help="run 2,5 then 5,2 -- guards against ordering artifacts")
    a = ap.parse_args()

    with Peeker() as p:
        p.wake()

        print("=" * 70)
        print("CONTROL -- is peek alive?")
        v = p.read32(KNOWN_TRUTH_ADDR)
        okc = (v == KNOWN_TRUTH_VAL)
        print("  0x%08X = %08X (want %08X)  %s"
              % (KNOWN_TRUTH_ADDR, v, KNOWN_TRUTH_VAL,
                 "PASS" if okc else "FAIL"))
        if not okc:
            print("  => INCONCLUSIVE: the instrument is not verified. Stop.")
            return 2
        print("=" * 70)

        orders = [[2, 5], [5, 2]] if a.both_orders else \
                 [[int(x) for x in a.order.split(",")]]

        results = []
        for oi, order in enumerate(orders, 1):
            print("\n" + "=" * 70)
            print("PASS %d -- order %s" % (oi, "->".join(map(str, order))))
            print("=" * 70)
            for d in order:
                results.append((d, run_arm(p, d, a.watch)))
                time.sleep(1.0)

        print("\n" + "=" * 70)
        print("VERDICT")
        print("=" * 70)
        d2 = [r for d, r in results if d == 2]
        d5 = [r for d, r in results if d == 5]
        a2 = sum(1 for r in d2 if r["advanced"])
        a5 = sum(1 for r in d5 if r["advanced"])
        print("  depth 2 (announce 0x01) advanced in %d/%d arms" % (a2, len(d2)))
        print("  depth 5 (announce 0xFF) advanced in %d/%d arms" % (a5, len(d5)))
        print()
        if a5 and not a2:
            print("  => THE ANNOUNCE BYTE IS THE MECHANISM.")
            print("     Same command code in both arms; only the flag differs.")
        elif a5 and a2:
            print("  => both arms advanced: the announce is NOT the")
            print("     discriminator, or something else is driving the chain.")
            print("     Check whether the bench is receiving real RKE traffic.")
        elif not a5 and not a2:
            print("  => neither advanced.  On a bench this may be a scope")
            print("     limit (no ignition, dormant path) rather than a")
            print("     refutation -- check whether the sub-state is 1.")
        else:
            print("  => only depth 2 advanced: unexpected, investigate.")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
