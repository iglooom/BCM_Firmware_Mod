#!/usr/bin/env python3
"""RFA simulator + lock-response observer for the bench BCM.

Impersonates the remote-keyless module on MS-CAN `0x100` and records the BCM's
reaction on `0x3A` (the lock-command frame that drives DDM/PDM).

Signals (docs/rke_0x100_lock.md §1, docs/rke-lock.md §4 - established before
this rig existed; this script re-tests them rather than assuming them):

  0x100  60 ms periodic, 8 bytes, idle payload 02 17 00 00 02 00 00 00
    d7 bit0 (0x01) = LOCK          d7 bit1 (0x02) = UNLOCK
    d6 bit2 (0x04) = UB / valid    (RFA asserts after rolling-code validation)
    d6[7:3] || d7[7:0]             = 13-bit command code
    d7 bit4, d6 bit5               = rolling counter
    d1 bit7 (0x80)                 = KEY OUTSIDE

  0x3A   the observable
    d3      = APP_lock_command  (01 LOCK / 02 UNLOCK)
    d1 bit6 = execute strobe    (ONE-SHOT, not a level)

  0x3A0  d0 hi-nibble = 4 -> ignition Run   (we do NOT transmit this by
         default; the BCM emits it - see --ign)

⚠ The MS bus sleeps independently.  Our own 60 ms 0x100 stream keeps it awake;
that is why the idle stream runs for the whole trial, not just during presses.

Usage:
  rfa_sim.py baseline  --secs 10
  rfa_sim.py press     --cmd lock   --n 5 --key-outside
  rfa_sim.py sweep     --nibble                 # command-enum sweep
Every run writes a timestamped JSON + raw candump log under work/bench/logs/.
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
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "logs")
IFACE = "can1"

RFA_ID = 0x100
LOCK_ID = 0x03A
IGN_ID = 0x3A0

IDLE = bytearray([0x02, 0x17, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
PERIOD = 0.060          # 60 ms, the RFA's native rate


# ---------------------------------------------------------------- raw CAN tx
def open_can(iface=IFACE):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def send(sock, can_id, data):
    data = bytes(data)[:8]
    sock.send(struct.pack("=IB3x8s", can_id, len(data), data.ljust(8, b"\0")))


# ------------------------------------------------------------ frame builders
def rfa_frame(cmd_bits=0, ub=False, key_outside=False, roll=0, code_hi=0x1F):
    """Build a 0x100 payload.

    cmd_bits : low bits of d7 (1=LOCK, 2=UNLOCK, 0=idle/release)
    code_hi  : the d6[7:3] part of the 13-bit code (0x1F seen on the wire)
    roll     : rolling counter, toggles d7 bit4 and d6 bit5
    """
    f = bytearray(IDLE)
    if key_outside:
        f[1] |= 0x80
    if cmd_bits == 0:
        f[6], f[7] = 0x20, 0x00          # the observed RELEASE word 0x2000
        return f
    d6 = (code_hi & 0x1F) << 3
    d7 = cmd_bits & 0xFF
    if roll & 1:
        d7 |= 0x10
    if roll & 2:
        d6 |= 0x20
    if ub:
        d6 |= 0x04
    f[6], f[7] = d6 & 0xFF, d7 & 0xFF
    return f


CMDS = {"idle": 0, "lock": 0x01, "unlock": 0x02}


# -------------------------------------------------------------- the observer
def start_capture(tag, ifaces=("can1",)):
    os.makedirs(LOGS, exist_ok=True)
    path = os.path.join(LOGS, "%s_%s.log" % (time.strftime("%Y%m%dT%H%M%S"), tag))
    p = subprocess.Popen(["candump", "-ta"] + list(ifaces),
                         stdout=open(path, "w"), stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    return p, path


def stop_capture(p):
    time.sleep(0.5)
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()


LINE = re.compile(r"\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-F]{3})\s+\[(\d+)\]\s+(.*)")


def parse(path):
    out = []
    with open(path) as fh:
        for ln in fh:
            m = LINE.match(ln.strip())
            if not m:
                continue
            t, iface, cid, dlc, data = m.groups()
            out.append((float(t), iface, int(cid, 16),
                        bytes(int(x, 16) for x in data.split())))
    return out


def analyse(frames, t0=None):
    """Summarise the observable: every distinct 0x3A payload + strobe events."""
    lock = [(t, d) for t, i, c, d in frames if c == LOCK_ID]
    ign = [(t, d) for t, i, c, d in frames if c == IGN_ID]
    payloads = Counter(d.hex(" ") for _, d in lock)
    d3 = Counter(d[3] for _, d in lock if len(d) > 3)
    strobes = [(t, d.hex(" ")) for t, d in lock if len(d) > 1 and d[1] & 0x40]
    return dict(
        lock_frames=len(lock),
        distinct_payloads=dict(payloads),
        d3_values={hex(k): v for k, v in d3.items()},
        strobe_count=len(strobes),
        strobes=[dict(t=round(t - (t0 or t), 3), payload=p) for t, p in strobes[:40]],
        ign_payloads=dict(Counter(d.hex(" ") for _, d in ign)),
    )


# ------------------------------------------------------------------ routines
def stream_idle(sock, secs, key_outside=False):
    """Keep the bus awake with the RFA's idle stream."""
    end = time.time() + secs
    while time.time() < end:
        send(sock, RFA_ID, rfa_frame(0, key_outside=key_outside))
        time.sleep(PERIOD)


def do_baseline(a):
    sock = open_can(a.iface)
    cap, path = start_capture("baseline")
    t0 = time.time()
    stream_idle(sock, a.secs, a.key_outside)
    stop_capture(cap)
    res = analyse(parse(path), t0)
    res["trial"] = "baseline"
    report(res, path, a)


def do_press(a):
    """n presses: burst of held frames, then release, then a gap."""
    sock = open_can(a.iface)
    cap, path = start_capture("press_%s" % a.cmd)
    t0 = time.time()
    marks = []
    stream_idle(sock, a.settle, a.key_outside)
    for k in range(a.n):
        marks.append(round(time.time() - t0, 3))
        held = int(a.hold / PERIOD)
        for j in range(held):
            send(sock, RFA_ID, rfa_frame(CMDS[a.cmd], ub=a.ub,
                                         key_outside=a.key_outside,
                                         roll=(k if a.roll else 0)))
            time.sleep(PERIOD)
        stream_idle(sock, a.gap, a.key_outside)   # release + inter-press gap
    stream_idle(sock, a.settle, a.key_outside)
    stop_capture(cap)
    res = analyse(parse(path), t0)
    res.update(trial="press", cmd=a.cmd, n=a.n, hold=a.hold,
               key_outside=a.key_outside, ub=a.ub, press_times=marks)
    report(res, path, a)


def do_sweep(a):
    """Sweep the low nibble of d7 to build the command-enum -> d3 table."""
    sock = open_can(a.iface)
    cap, path = start_capture("sweep_nibble")
    t0 = time.time()
    order = []
    stream_idle(sock, a.settle, a.key_outside)
    for nib in range(16):
        order.append(dict(nibble=nib, t=round(time.time() - t0, 3)))
        for j in range(int(a.hold / PERIOD)):
            send(sock, RFA_ID, rfa_frame(nib, ub=a.ub, key_outside=a.key_outside))
            time.sleep(PERIOD)
        stream_idle(sock, a.gap, a.key_outside)
    stop_capture(cap)
    frames = parse(path)
    # per-nibble slice of the observable
    per = {}
    for idx, o in enumerate(order):
        t_end = order[idx + 1]["t"] if idx + 1 < len(order) else 1e9
        sl = [(t, i, c, d) for t, i, c, d in frames
              if o["t"] <= (t - t0) < t_end]
        per[o["nibble"]] = analyse(sl, t0)
    res = dict(trial="sweep_nibble", order=order,
               per_nibble={str(k): v for k, v in per.items()})
    report(res, path, a)


def report(res, path, a):
    out = path.replace(".log", ".json")
    with open(out, "w") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps(res, indent=1))
    print("\nraw candump : %s" % path)
    print("summary json: %s" % out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["baseline", "press", "sweep"])
    ap.add_argument("--iface", default=IFACE)
    ap.add_argument("--cmd", default="lock", choices=list(CMDS))
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--hold", type=float, default=0.30, help="press hold, s")
    ap.add_argument("--gap", type=float, default=1.50, help="release gap, s")
    ap.add_argument("--settle", type=float, default=2.0)
    ap.add_argument("--secs", type=float, default=10.0)
    ap.add_argument("--key-outside", action="store_true")
    ap.add_argument("--ub", action="store_true", help="assert the UB/valid bit")
    ap.add_argument("--roll", action="store_true", help="increment rolling counter")
    a = ap.parse_args()
    {"baseline": do_baseline, "press": do_press, "sweep": do_sweep}[a.mode](a)


if __name__ == "__main__":
    main()
