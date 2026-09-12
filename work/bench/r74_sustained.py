#!/usr/bin/env python3
"""H5: does APP_req_word_74 b2 -> 0x06 require SUSTAINED activity?

Why H5.  Runs that saw 0x06:
    probe_read watch (17 probes)      - late in a long continuous session
    probe_read watch --only (3)       - immediately after the above
    r74_trigger.py                    - ~3 min of back-to-back bursts
Run that saw ZERO 0x06 even during 3 confirmed presses:
    r74_freerun.py                    - opened with a 2 s settle + 30 s QUIET
                                        window before the burst

Same probe set in the last two, so the probe set does not explain it.  The
discriminating variable is whether the module had been CONTINUOUSLY ACTIVE.

PREDICTION (H5): repeating identical bursts back-to-back with no long idle,
0x06 will be absent for the first few bursts and then start appearing; and
inserting a long quiet gap will "reset" that.

FALSIFIER: if 0x06 appears on burst 1 with the same probability as burst 8, H5
is wrong and the earlier absence needs another explanation.

Every burst is IDENTICAL (3 presses, gap 1.5) so burst index is the only
variable.  The initial value is recorded separately from edges, so a cell still
holding 06 from the previous burst is never miscounted as a new firing
(the bug that broke r74_trigger.py).

Output: work/bench/logs/r74_sustained.json
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
OUT = os.path.join(LOGS, "r74_sustained.json")
TESTER_ID, ECU_ID = 0x726, 0x72E
DID_R74, DID_LOCK = 0x4099, 0x0631


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


def burst(u, idx, presses=3, gap=1.5, secs=9.0):
    initial = None
    for _ in range(10):
        initial = u.read_did(DID_R74)
        if initial is not None:
            break
    pr = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "work/bench/rfa_sim.py"),
         "press", "--cmd", "lock", "--n", str(presses), "--gap", str(gap),
         "--key-outside"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    edges, last = [], initial
    locks, prev = 0, None
    while time.time() - t0 < secs:
        v = u.read_did(DID_R74)
        if v is not None and v != last:
            edges.append((round(time.time() - t0, 3), v))
            last = v
        lv = u.read_did(DID_LOCK)
        if lv is not None and lv != prev:
            if lv == "01":
                locks += 1
            prev = lv
    pr.wait(timeout=60)
    saw06 = initial == "06" or any(v == "06" for _, v in edges)
    return dict(burst=idx, initial=initial, edges=edges, locks=locks,
                saw06=saw06, new06=any(v == "06" for _, v in edges))


def main():
    u = Uds()
    u.wake()
    out = []

    print("== phase 1: 8 identical bursts, back-to-back, NO long idle ==")
    print("   (3 presses, gap 1.5 s, ~9 s window each)\n")
    for i in range(1, 9):
        r = burst(u, i)
        out.append(r)
        print("   burst %d: initial %s  locks %d  new 06: %-3s  edges %s"
              % (i, r["initial"], r["locks"], "YES" if r["new06"] else "no",
                 r["edges"][:6]))

    first_hit = next((r["burst"] for r in out if r["new06"]), None)
    print("\n   first burst showing a NEW 06: %s"
          % (first_hit if first_hit else "none in 8"))

    print("\n== phase 2: 45 s quiet, then repeat one identical burst ==")
    print("   (H5 predicts the quiet period resets whatever was accumulating)")
    time.sleep(45.0)
    r = burst(u, 99)
    out.append(r)
    print("   after-quiet burst: initial %s  locks %d  new 06: %s  edges %s"
          % (r["initial"], r["locks"], "YES" if r["new06"] else "no",
             r["edges"][:6]))

    os.makedirs(LOGS, exist_ok=True)
    json.dump(out, open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)

    print("\n== VERDICT ==")
    hits = [r["burst"] for r in out if r["new06"] and r["burst"] != 99]
    print("   bursts with a new 06: %s of 1..8" % (hits or "none"))
    live = all(r["locks"] > 0 for r in out)
    print("   stimulus confirmed in every burst: %s" % ("YES" if live else "NO"))
    if not live:
        print("   ⇒ INCONCLUSIVE - some bursts had no confirmed lock event,")
        print("     so absence of 06 there is not evidence (rule 27).")
        return
    if not hits:
        print("   ⇒ 0x06 did NOT reproduce in 8 identical bursts.")
        print("     H5 as stated is NOT supported, and the earlier sightings")
        print("     remain UNEXPLAINED - they are not reproduced by press")
        print("     bursts alone.  Do not attribute 0x06 to RKE.")
    elif min(hits) >= 3:
        print("   ⇒ consistent with H5: early bursts silent, later ones fire.")
        print("     first hit at burst %d" % min(hits))
        print("     after-quiet burst fired: %s" % out[-1]["new06"])
    else:
        print("   ⇒ 0x06 fires from burst %d - no warm-up needed, H5 unlikely."
              % min(hits))


if __name__ == "__main__":
    main()
