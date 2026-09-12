#!/usr/bin/env python3
"""BENCH: localise WHY enum 8 does not reach APP_power_mode = 4.

291 established (docs/bench_session_4.md): the stimulus lands in the firmware's own
RKE cell, the rig drives the BCM end to end (LOCK -> 0x3A d3 = 01 on the wire), the
mode cell is live (4 documented mode-1 pulses), and mode 4 never occurs.  Config
bytes were then measured and ACQUITTED (Sec.4.3).

This script attacks the two surviving leads, and -- the point -- it reads the guard's
OWN INPUTS rather than only its outcome, so a null localises to a term instead of
being another undifferentiated negative.

LEAD 4  missing vehicle context.  The BCM RECEIVES MS 0x3A0 (ignition status) on
        mb36, image 0x400006D0 (rx_frame_map.json), and nothing transmits it on the
        bench.  docs/key_outside_gate.md: d0 hi-nibble == 4 means Run.  We now
        synthesise it, so the BCM sees an ignition context for the first time.

LEAD 2  APP_lock_request_input 0x40008D2C == 0 in every sample of 291, while
        FUN_00087486's mode-4 arm needs == 1.

GUARD TERMS WATCHED (FUN_000ADADA, docs/remote_start.md Sec.7):
    DAT_40003C42        < 0        -> short-circuits the WHOLE guard (measured 0x00)
    (r31+0x94 >>0x1B)&7 == 7       -> state term;  r31 base UNKNOWN (Sec.7.0.2)
    (rke+0x82 & 0xF)    == 8       -> CONFIRMED reaching the cell by 291
    (rke+0x82 >>4 &1)   != 0       -> d7 bit4, the ROLLING-COUNTER bit

*** The d7-bit4 term is the cheap hypothesis this run exists to test. ***
291 sent roll=0,1,2,3... so d7 bit4 alternated; the guard needs it SET.  A press
whose frames all have bit4 = 0 can never pass.  Condition E holds bit4 high for the
whole press.

CONTROLS
  * peek liveness before AND after (rule 27).
  * stimulus verified from APP_rke_command_code, not assumed (rule 40 / Sec.8.6).
  * 0x3A0 injection verified by reading the BCM's own RX IMAGE 0x400006D0 back --
    if the image does not change, the frame was not accepted and any downstream
    null is void.  That is a real control, not a hope.
  * continuous 0x80 wire capture: power_mode is sampled at 62 ms by the BUS, which
    291 Sec.3.2 proved is the superior channel for this cell (the peek at ~13 Hz
    misses 60 ms pulses).
"""
import argparse
import json
import os
import re
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
IGN_ID = 0x3A0
IDLE = bytearray([0x02, 0x17, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
PERIOD = 0.060
IGN_PERIOD = 0.100

CELLS = {
    "power_mode_word": 0x40001D84,
    "rke_code": 0x40002DA2,
    "ign_rx_image": 0x400006D0,      # 0x3A0 d0 -- the injection control
    "lock_req_input": 0x40008D2C,
    "gate_3C42": 0x40003C42,
    "arming": 0x40008D75,
}


def open_can(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def send(sock, can_id, data):
    data = bytes(data)[:8]
    sock.send(struct.pack("=IB3x8s", can_id, len(data), data.ljust(8, b"\0")))


def rfa(enum_bits, roll=0, bit4=None, code_hi=0x1F):
    f = bytearray(IDLE)
    if enum_bits == 0:
        f[6], f[7] = 0x20, 0x00
        return f
    d6 = (code_hi & 0x1F) << 3
    d7 = enum_bits & 0xFF
    if bit4 is None:
        if roll & 1:
            d7 |= 0x10
    elif bit4:
        d7 |= 0x10
    if roll & 2:
        d6 |= 0x20
    f[6], f[7] = d6 & 0xFF, d7 & 0xFF
    return f


def ign_frame(run=True):
    """MS 0x3A0: d0 hi-nibble 4 = Run (docs/key_outside_gate.md)."""
    f = bytearray(8)
    f[0] = 0x40 if run else 0x00
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold", type=float, default=1.5)
    ap.add_argument("--gap", type=float, default=1.0)
    ap.add_argument("--null", type=float, default=5.0)
    ap.add_argument("--tag", default="rs2")
    args = ap.parse_args()

    os.makedirs(LOGS, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    cap_path = os.path.join(LOGS, "%s_%s_bus.log" % (stamp, args.tag))
    cap = subprocess.Popen(["candump", "-ta", "can0", "can1"],
                           stdout=open(cap_path, "w"), stderr=subprocess.DEVNULL)
    time.sleep(0.4)

    sock = open_can(IFACE_MS)
    results = {}
    try:
        with Peeker() as p:
            print("== liveness BEFORE =="); p.assert_live(); print("   OK")

            def phase(secs, enum_bits=0, bit4=None, ign=False, label=""):
                """Stream 0x100 (+0x3A0 when ign) while sampling cells."""
                samples = []
                t_end = time.time() + secs
                roll = 0
                nxt_rfa = nxt_ign = 0.0
                while time.time() < t_end:
                    now = time.time()
                    if now >= nxt_rfa:
                        send(sock, RFA_ID, rfa(enum_bits, roll=roll, bit4=bit4))
                        roll += 1
                        nxt_rfa = now + PERIOD
                    if ign and now >= nxt_ign:
                        send(sock, IGN_ID, ign_frame(True))
                        nxt_ign = now + IGN_PERIOD
                    for name, addr in CELLS.items():
                        try:
                            v = p.read32(addr)
                        except Exception:
                            v = None
                        samples.append((name, v))
                        if time.time() >= t_end:
                            break
                return samples

            def run(label, script):
                print("\n== %s ==" % label)
                alls = []
                for secs, enum_bits, bit4, ign, sub in script:
                    print("   %-26s %4.1fs enum=%-2s bit4=%-4s ign=%s"
                          % (sub, secs, enum_bits, bit4, ign))
                    alls += phase(secs, enum_bits, bit4, ign, sub)
                agg = {}
                for name in CELLS:
                    c = Counter(v for n, v in alls if n == name)
                    agg[name] = {("0x%08X" % k if k is not None else "ERR"): n
                                 for k, n in c.items()}
                pm = Counter((v >> 16) & 0xFF for n, v in alls
                             if n == "power_mode_word" and v is not None)
                print("      power_mode: %s" % dict(pm))
                print("      rke_code  : %s"
                      % {("0x%04X" % ((int(k, 16) >> 16) & 0xFFFF) if k != "ERR" else k): v
                         for k, v in agg["rke_code"].items()})
                print("      ign_image : %s" % agg["ign_rx_image"])
                results[label] = agg
                return agg

            run("null_before", [(args.null, 0, None, False, "idle")])

            # E: rolling-counter bit4 held HIGH (the guard needs it set)
            run("E_bit4_high", [
                (1.0, 0, None, False, "settle"),
                (args.hold, 8, True, False, "START bit4=1"),
                (args.gap, 0, None, False, "release"),
                (args.hold, 8, True, False, "START2 bit4=1"),
                (2.0, 0, None, False, "after"),
            ])

            # F: ignition context injected (lead 4) + bit4 high
            run("F_ign_plus_bit4", [
                (2.0, 0, None, True, "ign settle"),
                (args.hold, 8, True, True, "START ign+bit4"),
                (args.gap, 0, None, True, "release"),
                (args.hold, 8, True, True, "START2 ign+bit4"),
                (2.0, 0, None, True, "after"),
            ])

            # G: ignition + LOCK-then-START (the Sec.7.1 sequence) + bit4
            run("G_ign_lock_start", [
                (2.0, 0, None, True, "ign settle"),
                (args.hold, 1, True, True, "LOCK"),
                (args.gap, 0, None, True, "release"),
                (args.hold, 8, True, True, "START"),
                (args.gap, 0, None, True, "release"),
                (args.hold, 8, True, True, "START2"),
                (2.0, 0, None, True, "after"),
            ])

            run("null_after", [(args.null, 0, None, False, "idle")])

            print("\n== liveness AFTER =="); p.assert_live(); print("   OK")
    finally:
        sock.close()
        time.sleep(0.5)
        cap.send_signal(signal.SIGINT)
        try:
            cap.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cap.kill()

    out = os.path.join(LOGS, "%s_%s.json" % (stamp, args.tag))
    json.dump({"results": results, "bus": cap_path}, open(out, "w"), indent=1)
    print("\nwrote %s\nbus %s" % (out, cap_path))

    # ---- wire-side power_mode, the superior channel (Sec.3.2) --------------
    LINE = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-F]{3})\s+\[(\d+)\]\s+(.*)")
    f80, f3a0 = [], 0
    for ln in open(cap_path):
        m = LINE.match(ln.strip())
        if not m:
            continue
        t, ifc, cid, dlc, data = m.groups()
        d = bytes(int(x, 16) for x in data.split())
        if int(cid, 16) == 0x80 and ifc == "can1":
            f80.append((float(t), d))
        if int(cid, 16) == IGN_ID:
            f3a0 += 1
    print("\n=== WIRE power_mode over %d 0x80 frames ===" % len(f80))
    print("   %s" % dict(Counter((d[2] >> 5) & 7 for _, d in f80)))
    print("   0x3A0 frames on the bus: %d" % f3a0)
    print("\nCONTROL: if ign_rx_image never changed, the 0x3A0 injection was NOT")
    print("accepted and every ignition-condition null above is VOID (rule 27).")


main()
