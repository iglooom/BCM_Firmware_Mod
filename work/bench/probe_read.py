#!/usr/bin/env python3
"""Read the probe bank live while driving an RKE stimulus.

Run this AFTER flashing work/probe-bank/JV6T-14C094-AD_probe-bank.VBF.

Modes:
  idle     - read every probe once, no stimulus (post-flash sanity)
  watch    - poll every probe continuously during an RKE press and report which
             cells CHANGED, with timestamps relative to the press
  control  - the acceptance test: poll ONLY the positive-control probe (0x0631 =
             APP_lock_command) while pressing lock and unlock, and check that it
             reports the values the MS-CAN bus simultaneously shows on 0x3A d3

⚠ READ 'control' FIRST AND BELIEVE NOTHING ELSE UNTIL IT PASSES.
0x0631 watches a cell whose value we already know independently from the wire
(0x01 lock / 0x02 unlock / 0x06 the non-actuating command).  If the probe does
not track the bus, then the flash did not take, or the DID route does not read
what we think it reads, and every other probe in the bank is meaningless.

Usage:
    python3 work/bench/probe_read.py idle
    python3 work/bench/probe_read.py control
    python3 work/bench/probe_read.py watch --cmd lock
"""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
PLAN = os.path.join(ROOT, "work/owner/probe_bank_bytes.json")
LOGS = os.path.join(ROOT, "work/bench/logs")
IFACE, TESTER, ECU = "can0", "726", "72E"
TESTER_ID, ECU_ID = 0x726, 0x72E
CONTROL_DID = 0x0631
CONTROL_CELL = "0x40002e70"


# ---------------------------------------------------------------- raw SocketCAN
# ⚠ SPEED MATTERS AND IT IS ENTIRELY OURS TO LOSE.
# The first version of this file spawned a `candump` subprocess per read and
# managed 1.3 Hz - hopeless against the 0.10-0.30 s transients this bank exists
# to catch, and it would have produced a confident "nothing changed".  A single
# persistent raw CAN socket does 100 Hz on the same hardware (401/401 answered),
# with the ECU replying in ~9 ms median.  The 77x gap was pure host overhead.
class Uds:
    def __init__(self, iface=IFACE):
        self.s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.s.bind((iface,))
        self.s.settimeout(0.3)

    def send(self, cid, data):
        d = data + b"\x00" * (8 - len(data))
        self.s.send(struct.pack("=IB3x8s", cid, 8, d))

    def drain(self):
        self.s.settimeout(0.001)
        while True:
            try:
                self.s.recv(16)
            except Exception:
                break

    def tester_present(self):
        self.send(TESTER_ID, bytes([0x02, 0x3E, 0x80]))

    def read_did(self, did, to=0.25):
        self.drain()
        self.s.settimeout(to)
        self.send(TESTER_ID, bytes([0x03, 0x22, (did >> 8) & 0xFF, did & 0xFF]))
        t0 = time.time()
        while time.time() - t0 < to:
            try:
                raw = self.s.recv(16)
            except Exception:
                break
            cid, dlc, data = struct.unpack("=IB3x8s", raw)
            if (cid & 0x1FFFFFFF) != ECU_ID:
                continue
            if data[0] >> 4 == 0:
                n = data[0] & 0x0F
                body = data[1:1 + n]
                if body and body[0] == 0x62:
                    return body[3:].hex().upper()
                if body and body[0] == 0x7F:
                    return None
        return None

    def wake(self):
        for _ in range(10):
            self.tester_present()
            time.sleep(0.2)


def probes():
    return json.load(open(PLAN))["probes"]


def do_idle(a):
    u = Uds()
    u.wake()
    print("== probe bank, idle (no stimulus) ==")
    for p in probes():
        u.tester_present()
        v = u.read_did(int(p["did"], 16))
        print("   %s  %-12s = %-4s  %s"
              % (p["did"], p["watch"], v if v is not None else "NO-RESP",
                 p["why"][:44]))


def do_control(a):
    """The acceptance test: probe vs bus, same cell, same moment."""
    u = Uds()
    u.wake()
    print("== POSITIVE CONTROL: DID 0x%04X watches %s (APP_lock_command) =="
          % (CONTROL_DID, CONTROL_CELL))
    print("   the bus shows this same cell as MS 0x3A d3")
    print("   polling at ~100 Hz via a raw CAN socket\n")
    results = []
    for cmd, expect in (("lock", "01"), ("unlock", "02")):
        cap = subprocess.Popen(["candump", "-ta", "can1"],
                               stdout=subprocess.PIPE, text=True)
        time.sleep(0.3)
        pr = subprocess.Popen([sys.executable,
                               os.path.join(ROOT, "work/bench/rfa_sim.py"),
                               "press", "--cmd", cmd, "--n", "2", "--key-outside"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        samples = []
        t0 = time.time()
        while time.time() - t0 < 8.0:
            v = u.read_did(CONTROL_DID, to=0.05)
            if v:
                samples.append((round(time.time() - t0, 3), v))
        pr.wait(timeout=40)
        time.sleep(0.4)
        cap.terminate()
        out, _ = cap.communicate()
        bus = set()
        for ln in out.splitlines():
            # ⚠ candump has TWO output formats and they are not interchangeable:
            #   -L  ->  (ts) can1 03A#A040000100000000      <- '#'-joined
            #   -ta ->  (ts)  can1  03A   [8]  A0 40 00 01  <- spaced columns
            # We launch it with -ta, so a '03A#' regex matches NOTHING and the
            # bus set comes back empty - which then reads as "probe disagrees
            # with the bus" and condemns a bank that is actually working.
            # Parse the spaced form, and accept the '#' form too.
            m = re.search(r"\s03A\s+\[\d\]\s+((?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})", ln)
            if m:
                bus.add(m.group(1).split()[3].upper())
                continue
            m = re.search(r"\s03A#([0-9A-Fa-f]+)", ln)
            if m and len(m.group(1)) >= 8:
                bus.add(m.group(1)[6:8].upper())
        if not bus:
            print("   !! NO 0x3A frames captured - the bus observer is broken,")
            print("      which is NOT evidence about the probe.  Check candump")
            print("      format/interface before reading anything into this.")
        seen = set(v for _, v in samples)
        print("   %-7s %d samples | probe saw %-14s | bus 0x3A d3 saw %s"
              % (cmd, len(samples), ",".join(sorted(seen)) or "-",
                 ",".join(sorted(bus)) or "-"))
        for t, v in samples:
            if v != samples[0][1]:
                print("        first change at t=%.3fs -> %s" % (t, v))
                break
        results.append((cmd, expect, seen, bus))

    print("\n== verdict ==")
    ok = True
    observer_ok = all(bus for _, _, _, bus in results)
    for cmd, expect, seen, bus in results:
        hit = expect in seen
        agree = bool(seen & bus)
        print("   %-7s expected %s | probe reported it: %-3s | probe∩bus: %s"
              % (cmd, expect, "YES" if hit else "NO",
                 "YES" if agree else ("NO" if bus else "n/a - observer dead")))
        ok = ok and hit and agree
    if not observer_ok:
        print("\n   ✗ INCONCLUSIVE - the bus observer captured nothing, so the")
        print("     probe-vs-bus comparison could not be made.  This says")
        print("     NOTHING about the probes.  Fix the observer and re-run.")
        return False
    if ok:
        print("\n   ✓ CONTROL PASSES - the probe tracks a cell we can see on the")
        print("     wire.  The rest of the bank may now be believed.")
    else:
        print("\n   ✗ CONTROL FAILS - do NOT trust any other probe.")
        print("     Either the flash did not take, or the DID route reads")
        print("     something other than what we think.")
        print("     (Sample rate is NOT a plausible excuse at ~100 Hz.)")
    return ok


def do_watch(a):
    u = Uds()
    u.wake()
    ps = probes()
    if a.only:
        want = {x.upper() for x in a.only.split(",")}
        ps = [p for p in ps if p["did"].upper() in want]
        missing = want - {p["did"].upper() for p in ps}
        if missing:
            raise SystemExit("unknown DID(s): %s" % ",".join(sorted(missing)))
    print("== watching %d probes across an RKE '%s' press ==" % (len(ps), a.cmd))
    base = {}
    for p in ps:
        base[p["did"]] = u.read_did(int(p["did"], 16))
    print("   baseline captured; polling round-robin at ~100 Hz/read\n")

    pr = subprocess.Popen([sys.executable, os.path.join(ROOT, "work/bench/rfa_sim.py"),
                           "press", "--cmd", a.cmd, "--n", str(a.n),
                           "--gap", str(a.gap), "--key-outside"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    seen = {p["did"]: set() for p in ps}
    trace = {p["did"]: [] for p in ps}
    nread = 0
    while time.time() - t0 < a.secs:
        for p in ps:
            v = u.read_did(int(p["did"], 16), to=0.05)
            nread += 1
            if v is not None:
                seen[p["did"]].add(v)
                if not trace[p["did"]] or trace[p["did"]][-1][1] != v:
                    trace[p["did"]].append((round(time.time() - t0, 3), v))
    pr.wait(timeout=40)
    print("   %d reads in %.1fs (%.0f Hz aggregate, %.1f Hz per probe)"
          % (nread, a.secs, nread / a.secs, nread / a.secs / len(ps)))

    print("\n== cells that CHANGED during the press ==")
    changed = 0
    for p in ps:
        vals = seen[p["did"]]
        b = base[p["did"]]
        if len(vals) > 1 or (b is not None and vals and vals != {b}):
            changed += 1
            print("   %s %-12s base %-4s -> %s   %s"
                  % (p["did"], p["watch"], b, ",".join(sorted(vals)), p["why"][:40]))
            for t, v in trace[p["did"]][:6]:
                print("        t=%.3fs %s" % (t, v))
    if not changed:
        print("   none")
        print("\n   ⚠ Before concluding anything: did the CONTROL pass, and did the")
        print("     stimulus actually fire?  A silent rfa_sim failure looks exactly")
        print("     like this (see live_debug_uds.md §8.6).")
    print("\n   %d of %d probes moved" % (changed, len(ps)))
    os.makedirs(LOGS, exist_ok=True)
    json.dump(dict(cmd=a.cmd, baseline=base, reads=nread,
                   observed={k: sorted(v) for k, v in seen.items()},
                   trace=trace),
              open(os.path.join(LOGS, "probe_watch_%s.json" % a.cmd), "w"), indent=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["idle", "control", "watch"])
    ap.add_argument("--cmd", default="lock", choices=["lock", "unlock"])
    ap.add_argument("--secs", type=float, default=8.0)
    ap.add_argument("--only", default=None,
                    help="comma-separated DIDs to watch (fewer probes = much "
                         "higher per-probe sample rate, which is what resolves "
                         "ordering; 17 probes gives only ~5.8 Hz each)")
    ap.add_argument("--n", type=int, default=3, help="number of presses")
    ap.add_argument("--gap", type=float, default=1.5,
                    help="inter-press gap. VARY THIS to tell a causal offset "
                         "from a phase coincidence: a real lag stays constant, "
                         "an artifact of two signals sharing the press cadence "
                         "moves with the gap.")
    a = ap.parse_args()
    {"idle": do_idle, "control": do_control, "watch": do_watch}[a.mode](a)


if __name__ == "__main__":
    main()
