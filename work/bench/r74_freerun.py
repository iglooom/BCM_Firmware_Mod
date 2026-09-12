#!/usr/bin/env python3
"""Is APP_req_word_74 b2 (0x40008E76) free-running? The decisive control.

WHY THIS EXISTS - r74_trigger.py produced a verdict its own raw data refutes:

  BUG A  state leaked between back-to-back trials.  The trace records the FIRST
         sample as a "change" (no previous value exists), so a cell still
         holding 06 from the PREVIOUS condition was counted as a fresh firing
         at t=0.006.  Inflated every "fired" count.
  BUG B  the edge times are NOT stimulus-locked.  3.510 appears at gap=0.6 AND
         gap=2.5; 2.995 at gap=1.5 AND gap=0.6.  Press times move with the gap
         (2.0 + k*(0.3+gap)); these do not.
  BUG C  the H4 "free-running" control was 10 s and ran FIRST, before any press.
         If the mechanism is armed by a press and then free-runs, that control
         is blind to it by construction.

So the reported "needs >= 3 presses" (H3) is unsupported.

THE DECISIVE MEASUREMENT: watch the cell for a LONG time with NO stimulus,
AFTER a burst has occurred.  Predictions:

  free-running     -> keeps toggling 00<->06 with a characteristic period,
                      indefinitely, with no presses at all.
  press-triggered  -> settles and stays settled once the presses stop.

This also measures the PERIOD, which is the thing that identifies the
mechanism: ~2.5 s and ~3.6 s gaps between edges were visible in the bad data,
which smells like a periodic task, not a command handoff.

Output: work/bench/logs/r74_freerun.json
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
LOGS = os.path.join(ROOT, "work/bench/logs")
OUT = os.path.join(LOGS, "r74_freerun.json")
TESTER_ID, ECU_ID = 0x726, 0x72E
DID_R74 = 0x4099
DID_LOCK = 0x0631


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


def watch(u, secs, label, settle_first=True):
    """Poll r74 (+lock as liveness) for `secs`.  Records the INITIAL value
    separately from subsequent EDGES, so a leaked state can never be counted
    as a firing (bug A)."""
    if settle_first:
        # let any previous activity finish before the window opens
        time.sleep(2.0)
    initial = None
    for _ in range(10):
        initial = u.read_did(DID_R74)
        if initial is not None:
            break
    t0 = time.time()
    edges, last = [], initial
    lock_seen = 0
    prev_lock = None
    while time.time() - t0 < secs:
        v = u.read_did(DID_R74)
        if v is not None and v != last:
            edges.append((round(time.time() - t0, 3), v))
            last = v
        lv = u.read_did(DID_LOCK)
        if lv is not None and lv != prev_lock:
            if lv == "01":
                lock_seen += 1
            prev_lock = lv
    return dict(label=label, secs=secs, initial=initial, edges=edges,
                n_edges=len(edges), lock_events=lock_seen)


def periods(edges, value="06"):
    ts = [t for t, v in edges if v == value]
    return [round(b - a, 3) for a, b in zip(ts, ts[1:])]


def main():
    u = Uds()
    u.wake()
    out = []

    print("== A. long quiet window, BEFORE any press this session ==")
    a1 = watch(u, 30.0, "quiet-before")
    out.append(a1)
    print("   initial %s, %d edge(s) in 30 s, lock events %d"
          % (a1["initial"], a1["n_edges"], a1["lock_events"]))
    if a1["edges"]:
        print("      edges: %s" % a1["edges"][:10])
        print("      00->06 intervals: %s" % periods(a1["edges"]))

    print("\n== B. fire one burst of 3 presses ==")
    pr = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "work/bench/rfa_sim.py"),
         "press", "--cmd", "lock", "--n", "3", "--gap", "1.5", "--key-outside"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    b = watch(u, 12.0, "during-burst", settle_first=False)
    pr.wait(timeout=60)
    out.append(b)
    print("   initial %s, %d edge(s), lock events %d"
          % (b["initial"], b["n_edges"], b["lock_events"]))
    print("      edges: %s" % b["edges"][:10])

    print("\n== C. long quiet window AFTER the burst (the decisive one) ==")
    c = watch(u, 40.0, "quiet-after")
    out.append(c)
    print("   initial %s, %d edge(s) in 40 s, lock events %d"
          % (c["initial"], c["n_edges"], c["lock_events"]))
    if c["edges"]:
        print("      edges: %s" % c["edges"][:14])
        print("      00->06 intervals: %s" % periods(c["edges"]))

    os.makedirs(LOGS, exist_ok=True)
    json.dump(out, open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)

    print("\n== VERDICT ==")
    quiet_edges = a1["n_edges"] + c["n_edges"]
    print("   edges with NO stimulus: %d (before) + %d (after) = %d over 70 s"
          % (a1["n_edges"], c["n_edges"], quiet_edges))
    if quiet_edges == 0:
        print("   ⇒ the cell does NOT move without a stimulus.")
        print("     Press-triggered remains viable; r74_trigger.py must be")
        print("     rerun with the leak fixed before any H1/H2/H3 claim.")
    else:
        ivs = periods(a1["edges"]) + periods(c["edges"])
        print("   ⇒ FREE-RUNNING: the cell toggles with no presses at all.")
        if ivs:
            print("     00->06 intervals (s): %s" % ivs)
            print("     mean %.3f s" % (sum(ivs) / len(ivs)))
        print("     ⇒ APP_req_word_74 b2 = 0x06 is NOT an RKE handoff.")
        print("       docs/bench_session_2.md §4.1 must be corrected: the")
        print("       'runtime refutation of layer 36' was watching a periodic")
        print("       task that happens to pass through 0x06.")


if __name__ == "__main__":
    main()
