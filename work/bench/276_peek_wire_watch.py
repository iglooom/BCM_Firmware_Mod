#!/usr/bin/env python3
"""High-rate peek watch of a few cells, correlated against the MS-CAN wire.

This is the "peek + wire simultaneously" pattern of docs/peek_tool.md §6, and
it is the instrument the coarse scan (275) cannot be: watching 3-6 cells gives
~20-30 Hz each instead of one sample per 5 s, which is what it takes to see a
cell that pulses for a few hundred ms.

The wire channel is not decoration -- it is the ACCEPTANCE TEST.  MS `0x3A` d3
IS `APP_lock_command` on the bus (proven three independent ways, layer 36 §7).
So peeking 0x40002E70 while capturing 0x3A asks the instrument to agree with a
channel it does not control.  If the two disagree, the peek reading is void, no
matter how clean it looks.

Both candump output formats are parsed (`-L` and `-ta`): parsing only one of
them is precisely what made bench session 2 report a working flash as a
failure (§3.1).  An empty capture is reported INCONCLUSIVE, never FAIL
(AGENTS.md rule 27).

Usage:
  python3 work/bench/276_peek_wire_watch.py --cells 40002E70,40008E74 \
        --presses 6 --gap 1.2
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

NAMED = {
    0x40002DA0: "APP_rke_command_code (word)",
    0x40002E6C: "unnamed - highest-duty scan candidate",
    0x40002E70: "APP_lock_command",
    0x40008D2C: "APP_lock_request_input",
    0x40008D68: "unnamed - scan candidate 10/12",
    0x40008E74: "APP_req_word_74",
    0x40008EF4: "unnamed - scan candidate 8/12",
    0x40009034: "APP_rke_cmd_bits_34",
}

# candump -ta :  (1757.6) can1 03A [8] A0 40 00 01 00 00 00 00
RE_TA = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]{3})\s+\[(\d+)\]\s+(.*)")
# candump -L  :  (1757.6) can1 03A#A040000100000000
RE_L = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]{3})#([0-9A-Fa-f]*)")


def parse_candump(path):
    """Parse BOTH formats.  Returns [(t, can_id, bytes)]."""
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


def start_capture(tag, iface="can1"):
    os.makedirs(LOGS, exist_ok=True)
    path = os.path.join(LOGS, "%s_%s.log" % (time.strftime("%Y%m%dT%H%M%S"), tag))
    p = subprocess.Popen(["candump", "-ta", iface],
                         stdout=open(path, "w"), stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    return p, path


def stop_capture(p):
    time.sleep(0.4)
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()


def start_stimulus(n, hold, gap, cmd="lock"):
    log = os.path.join(LOGS, "%s_stim.log" % time.strftime("%Y%m%dT%H%M%S"))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "rfa_sim.py"), "press",
         "--cmd", cmd, "--n", str(n), "--hold", str(hold),
         "--gap", str(gap), "--settle", "1.0"],
        stdout=open(log, "w"), stderr=subprocess.STDOUT)
    return proc, log


def pair_nearest(ea, eb, window=0.5):
    """Pair each edge in `ea` with its NEAREST neighbour in `eb`.

    AGENTS.md rule 26: pairing an event with the next RISING transition instead
    of its nearest neighbour manufactured a 1040 ms "pipeline stage" that did
    not exist.  Nearest-neighbour pairing corrected it to +-10 ms, i.e. one
    event.  This function exists so that rule is enforced by code, not memory.
    """
    out = []
    for ta, va in ea:
        best = None
        for tb, vb in eb:
            d = tb - ta
            if abs(d) <= window and (best is None or abs(d) < abs(best[0])):
                best = (d, tb, vb)
        if best:
            out.append((ta, va, best[1], best[2], best[0]))
    return out


def order_report(cells, initial, trace, names):
    """Report pairwise offsets between cells, nearest-neighbour paired.

    Prints the offsets but deliberately draws NO causal conclusion: a constant
    offset between two signals locked to the same press cadence is a phase
    coincidence, not a lag, until the run is repeated at a different --gap and
    the offset survives (rule 26).  The script says so every time.
    """
    ed = {c: [(t, v) for t, cc, v in trace if cc == c] for c in cells}
    print("\nPAIRWISE OFFSETS (nearest-neighbour pairing, rule 26)")
    for i, ca in enumerate(cells):
        for cb in cells[i + 1:]:
            pairs = pair_nearest(ed[ca], ed[cb])
            if not pairs:
                print("  0x%08X vs 0x%08X : no pairs within window" % (ca, cb))
                continue
            ds = [p[4] for p in pairs]
            mean = sum(ds) / len(ds)
            spread = max(ds) - min(ds)
            print("  0x%08X -> 0x%08X : n=%d  mean %+.3f s  spread %.3f s"
                  % (ca, cb, len(ds), mean, spread))
    print("  ⚠ A constant offset here is NOT a lag. Re-run at a different")
    print("    --gap: a causal lag survives, a cadence artifact moves.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cells", default="40002E70",
                    help="comma-separated hex word addresses")
    ap.add_argument("--presses", type=int, default=6)
    ap.add_argument("--hold", type=float, default=0.30)
    ap.add_argument("--gap", type=float, default=1.20)
    ap.add_argument("--cmd", default="lock")
    ap.add_argument("--secs", type=float, default=0.0,
                    help="watch duration; default = until stimulus ends")
    a = ap.parse_args()

    cells = [int(c, 16) for c in a.cells.split(",")]
    print("watching %d cells: %s" % (len(cells),
                                     ", ".join("0x%08X" % c for c in cells)))

    with Peeker() as p:
        p.assert_live()

        cap, cappath = start_capture("peekwire")
        stim, stimlog = start_stimulus(a.presses, a.hold, a.gap, a.cmd)
        t0 = time.time()
        trace = []          # (t, addr, value) -- only on CHANGE
        last = {}
        initial = {}
        n = 0
        while stim.poll() is None or (a.secs and time.time() - t0 < a.secs):
            for c in cells:
                try:
                    v = p.read32(c)
                except PeekError:
                    continue
                n += 1
                t = round(time.time() - t0, 3)
                if c not in last:
                    # The FIRST sample is not a change -- recording it as one
                    # is what inflated every count in bench session 2 §8.1.
                    initial[c] = v
                    last[c] = v
                    continue
                if v != last[c]:
                    trace.append((t, c, v))
                    last[c] = v
            if a.secs and time.time() - t0 > a.secs:
                break
        dur = time.time() - t0
        stop_capture(cap)
        try:
            stim.wait(timeout=10)
        except subprocess.TimeoutExpired:
            stim.kill()

    print("\n%d reads in %.1f s = %.1f Hz aggregate, %.1f Hz per cell"
          % (n, dur, n / dur, n / dur / len(cells)))

    # ------------------------------------------------------- the wire channel
    frames = parse_candump(cappath)
    lock = [(t, d) for t, c, d in frames if c == LOCK_ID and len(d) > 3]
    if not lock:
        print("\n!! bus observer captured NO 0x%03X frames." % LOCK_ID)
        print("   INCONCLUSIVE -- a dead instrument is not evidence about the")
        print("   subject (AGENTS.md rule 27).  Check `candump can1`.")
        wire_ok = None
        wire_d3 = set()
        wire_edges = []
    else:
        wt0 = lock[0][0]
        wire_d3 = {d[3] for _, d in lock}
        wire_edges, prev = [], None
        for t, d in lock:
            if prev is not None and d[3] != prev:
                wire_edges.append((round(t - wt0, 3), d[3]))
            prev = d[3]
        wire_ok = True
        print("\nWIRE  0x%03X: %d frames, d3 values %s, %d d3 edges"
              % (LOCK_ID, len(lock), sorted(hex(v) for v in wire_d3),
                 len(wire_edges)))
        print("      first edges: %s" % [(t, hex(v)) for t, v in wire_edges[:8]])

    # ------------------------------------------------------ the peek channel
    print("\nPEEK:")
    for c in cells:
        vals = {initial[c]} | {v for _, cc, v in trace if cc == c}
        edges = [(t, v) for t, cc, v in trace if cc == c]
        print("  0x%08X  %-34s initial=0x%08X  %d changes  values=%s"
              % (c, NAMED.get(c, ""), initial.get(c, 0), len(edges),
                 sorted("0x%08X" % v for v in vals)))
        for t, v in edges[:10]:
            print("        t=%7.3f  0x%08X" % (t, v))

    if len(cells) > 1:
        order_report(cells, initial, trace, NAMED)

    # -------------------------------------------------------- adjudication
    lc = 0x40002E70
    if lc in cells:
        print("\n" + "=" * 64)
        peek_bytes = {(v >> 24) & 0xFF
                      for v in ({initial[lc]} | {v for _, cc, v in trace
                                                 if cc == lc})}
        print("ACCEPTANCE: peek 0x%08X b0 vs wire 0x03A d3" % lc)
        print("  peek b0 saw : %s" % sorted(hex(v) for v in peek_bytes))
        print("  wire d3 saw : %s" % sorted(hex(v) for v in wire_d3))
        if wire_ok is None:
            print("  => INCONCLUSIVE (bus observer dead)")
        elif peek_bytes & wire_d3:
            print("  => AGREE: peek reads the cell the wire carries")
        else:
            print("  => DISAGREE. Either 0x%08X is not the cell packed into" % lc)
            print("     0x03A d3, or the peek read of this region is wrong.")
            print("     Do not use any reading of this region until resolved.")
        print("=" * 64)

    out = os.path.join(LOGS, "%s_peekwire.json" % time.strftime("%Y%m%dT%H%M%S"))
    with open(out, "w") as fh:
        json.dump(dict(
            cells=[hex(c) for c in cells],
            rate_hz=round(n / dur / len(cells), 2),
            initial={hex(k): hex(v) for k, v in initial.items()},
            trace=[[t, hex(c), hex(v)] for t, c, v in trace],
            wire_d3=sorted(hex(v) for v in wire_d3),
            wire_edges=[[t, hex(v)] for t, v in wire_edges],
            candump=cappath, stimulus=stimlog,
        ), fh, indent=2)
    print("\nwrote %s" % out)


if __name__ == "__main__":
    main()
