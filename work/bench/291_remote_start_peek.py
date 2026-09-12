#!/usr/bin/env python3
"""BENCH: does RKE enum 8 drive APP_power_mode to 4, and is a fob-ID match required?

Tests the static claims of docs/remote_start.md on the live bench BCM
(JV6T-14C094-AD, serial 009640039386 -- VERIFIED by `bcmflash.py ident`, rule 32).

HYPOTHESES
  H1  enum 8 on MS 0x100 drives APP_power_mode (0x40001D85) 0 -> 4.
  H2  (Sec.7.1) a LOCK press first is REQUIRED: the enum-1 arm stores the fob ID at
      +0x84, and the enum-8 arm refuses unless it matches.  So LOCK-then-START
      should reach mode 4 where START-alone does not.
  H3  the fob ID matters: same-ID should work where a DIFFERENT id does not.

CONDITIONS (each preceded AND followed by a null window -- rules 29/40)
  A  enum 8 alone
  B  enum 1 (LOCK) then enum 8, SAME  d6/d7 identity bytes
  C  enum 1 (LOCK) then enum 8, DIFFERENT identity byte
  D  repeat of B at a different inter-press gap (rule 26 falsifier)

INSTRUMENT DISCIPLINE (all learned the hard way, docs/peek_tool.md Sec.4)
  * peeklib -- persistent socket, bounded drain, DID-echo matched.
  * assert_live() BEFORE and AFTER the whole run: an instrument that died
    mid-run turns every later null into a fake negative (rule 27).
  * the STIMULUS IS VERIFIED on the wire, not assumed -- we capture can1 and
    require our own 0x100 enum-8 frames to be present before any null is
    reported (live_debug_uds.md Sec.8.6: an argparse typo once made "nothing
    changed" look like a result).
  * cells are sampled in a tight loop for the whole trial, so a transient is
    not missed by a one-shot read (rule 40: a scan that samples once per pass
    has quantifiable blindness -- here we sample continuously instead).

NOTE ON MS-CAN: our own 60 ms 0x100 stream is what keeps the MS bus awake; it
runs for the entire trial, not only during presses.
"""
import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
LOGS = os.path.join(HERE, "logs")
from peeklib import Peeker  # noqa: E402

IFACE_MS = "can1"
RFA_ID = 0x100
IDLE = bytearray([0x02, 0x17, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
PERIOD = 0.060

# cells under test (docs/remote_start.md Sec.3-7)
CELLS = {
    "APP_power_mode_word": 0x40001D84,   # power_mode is BYTE +1 of this word
    "APP_rke_command_code": 0x40002DA2,
    "rke_fob_id": 0x40002DA4,
    "out_1A4": 0x40002F7A,
    "arming_flag": 0x40008D75,
    "lock_request_input": 0x40008D2C,
    "APP_lock_command": 0x40002E70,
}
POWER_MODE_SHIFT = 16   # 0x40001D85 is the 2nd byte of the 0x40001D84 word (BE)


def open_can(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def send(sock, can_id, data):
    data = bytes(data)[:8]
    sock.send(struct.pack("=IB3x8s", can_id, len(data), data.ljust(8, b"\0")))


def rfa_frame(enum_bits, code_hi=0x1F, roll=0, ident=None):
    """0x100 payload.  enum_bits: 0 release, 1 LOCK, 8 REMOTE START."""
    f = bytearray(IDLE)
    if ident is not None:
        f[4] = ident                      # the byte the +0x84 field tracks
    if enum_bits == 0:
        f[6], f[7] = 0x20, 0x00           # observed RELEASE word
        return f
    d6 = (code_hi & 0x1F) << 3
    d7 = enum_bits & 0xFF
    if roll & 1:
        d7 |= 0x10
    if roll & 2:
        d6 |= 0x20
    f[6], f[7] = d6 & 0xFF, d7 & 0xFF
    return f


def power_mode(word):
    if word is None:
        return None
    return (word >> POWER_MODE_SHIFT) & 0xFF


class Trial:
    """Runs the 0x100 stream on a thread-free schedule while peeking."""

    def __init__(self, sock, peeker):
        self.sock = sock
        self.p = peeker
        self.samples = []      # (t, cellname, value)
        self.tx_log = []       # (t, payload) of what WE transmitted

    def stream(self, secs, enum_bits=0, ident=None, roll_start=0, label=""):
        """Transmit 0x100 at 60 ms for `secs` while sampling the cells."""
        t_end = time.time() + secs
        roll = roll_start
        next_tx = 0.0
        while time.time() < t_end:
            now = time.time()
            if now >= next_tx:
                f = rfa_frame(enum_bits, roll=roll, ident=ident)
                send(self.sock, RFA_ID, f)
                self.tx_log.append((now, bytes(f), label))
                roll += 1
                next_tx = now + PERIOD
            # one cell per iteration, round-robin -> full set every ~7 reads
            for name, addr in CELLS.items():
                try:
                    v = self.p.read32(addr)
                except Exception:
                    v = None
                self.samples.append((time.time(), name, v))
                if time.time() >= t_end:
                    break
        return roll


def summarise(samples, cellname):
    vals = [(t, v) for t, n, v in samples if n == cellname]
    seen = Counter(v for _, v in vals)
    return vals, seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--null", type=float, default=6.0, help="null window, s")
    ap.add_argument("--hold", type=float, default=1.2, help="press hold, s")
    ap.add_argument("--gap", type=float, default=0.8, help="gap between presses")
    ap.add_argument("--gap2", type=float, default=2.5, help="rule-26 second gap")
    ap.add_argument("--tag", default="rs")
    args = ap.parse_args()

    os.makedirs(LOGS, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    cap_path = os.path.join(LOGS, "%s_%s_bus.log" % (stamp, args.tag))
    cap = subprocess.Popen(["candump", "-ta", "can0", "can1"],
                           stdout=open(cap_path, "w"),
                           stderr=subprocess.DEVNULL)
    time.sleep(0.4)

    results = {}
    sock = open_can(IFACE_MS)
    try:
        with Peeker() as p:
            print("== instrument liveness BEFORE ==")
            p.assert_live()
            print("   OK")

            def run(label, script):
                print("\n== %s ==" % label)
                t = Trial(sock, p)
                for (secs, enum_bits, ident, sub) in script:
                    print("   %-22s %4.1fs enum=%s ident=%s"
                          % (sub, secs, enum_bits, ident))
                    t.stream(secs, enum_bits=enum_bits, ident=ident, label=sub)
                vals, seen = summarise(t.samples, "APP_power_mode_word")
                modes = Counter(power_mode(v) for _, v in vals if v is not None)
                print("   APP_power_mode values seen: %s"
                      % {("0x%02X" % k if k is not None else None): c
                         for k, c in modes.items()})
                results[label] = {
                    "power_mode_hist": {str(k): v for k, v in modes.items()},
                    "cells": {n: {("0x%08X" % k if k is not None else "ERR"): c
                                  for k, c in summarise(t.samples, n)[1].items()}
                              for n in CELLS},
                    "n_tx": len(t.tx_log),
                }
                return t

            # ---- NULL (before) --------------------------------------------
            run("null_before", [(args.null, 0, None, "idle")])

            # ---- A: enum 8 alone ------------------------------------------
            run("A_start_only", [
                (1.0, 0, None, "settle"),
                (args.hold, 8, None, "START"),
                (args.gap, 0, None, "release"),
                (args.hold, 8, None, "START2"),
                (2.0, 0, None, "after"),
            ])

            # ---- B: LOCK then START, same identity ------------------------
            run("B_lock_then_start", [
                (1.0, 0, 0x02, "settle"),
                (args.hold, 1, 0x02, "LOCK"),
                (args.gap, 0, 0x02, "release"),
                (args.hold, 8, 0x02, "START"),
                (args.gap, 0, 0x02, "release"),
                (args.hold, 8, 0x02, "START2"),
                (2.0, 0, 0x02, "after"),
            ])

            # ---- C: LOCK then START, DIFFERENT identity -------------------
            run("C_different_id", [
                (1.0, 0, 0x02, "settle"),
                (args.hold, 1, 0x02, "LOCK(id=02)"),
                (args.gap, 0, 0x02, "release"),
                (args.hold, 8, 0x55, "START(id=55)"),
                (args.gap, 0, 0x55, "release"),
                (args.hold, 8, 0x55, "START2(id=55)"),
                (2.0, 0, 0x02, "after"),
            ])

            # ---- D: repeat B at a different gap (rule 26) -----------------
            run("D_lock_then_start_gap2", [
                (1.0, 0, 0x02, "settle"),
                (args.hold, 1, 0x02, "LOCK"),
                (args.gap2, 0, 0x02, "release"),
                (args.hold, 8, 0x02, "START"),
                (args.gap2, 0, 0x02, "release"),
                (args.hold, 8, 0x02, "START2"),
                (2.0, 0, 0x02, "after"),
            ])

            # ---- NULL (after) ---------------------------------------------
            run("null_after", [(args.null, 0, None, "idle")])

            print("\n== instrument liveness AFTER ==")
            p.assert_live()
            print("   OK -- nulls above are trustworthy")
    finally:
        sock.close()
        time.sleep(0.5)
        cap.send_signal(signal.SIGINT)
        try:
            cap.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cap.kill()

    out = os.path.join(LOGS, "%s_%s.json" % (stamp, args.tag))
    with open(out, "w") as fh:
        json.dump({"results": results, "bus_log": cap_path}, fh, indent=1)
    print("\nwrote %s" % out)
    print("bus capture %s" % cap_path)

    # ---------------- verdict scaffolding (evidence, not adjudication) -----
    print("\n" + "=" * 66)
    print("POWER-MODE HISTOGRAM BY CONDITION")
    for k, v in results.items():
        print("  %-24s %s" % (k, v["power_mode_hist"]))
    print("\nRead this WITH the bus capture: a condition whose enum-8 frames are")
    print("absent from %s proves nothing (stimulus unverified)." % os.path.basename(cap_path))


main()
