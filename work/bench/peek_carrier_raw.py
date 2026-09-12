#!/usr/bin/env python3
"""RAW adjudication of the C2/C3 results from peek_carrier_probe.py.

Why: that run reported every 0x31 and 0x23 probe as
"POS(multiframe) sid=0x7F total=72 / 92 / 112 / 132 / 152 / 172" -- a value
climbing by EXACTLY 20 per call.  A monotonic counter is the signature of an
instrument artifact, not of six different ECU answers (AGENTS.md rule 8: a
result with a suspicious regularity is a broken scan until proven otherwise).

Suspected cause: the previous request's multi-frame reply was never fully
drained, so collect() returns a STALE consecutive frame whose first byte is a
sequence number (0x2N), which parse() then misreads as a first frame.

This script prints EVERY raw 0x72E frame for each probe, with no
classification at all, so the bytes decide.
"""
import os
import socket
import struct
import sys
import time

IFACE = "can0"
TESTER = 0x726
ECU = 0x72E

PROBES = [
    ("22 0631            (control: known good)", [0x22, 0x06, 0x31]),
    ("22 0631 401B 4099  (3 real DIDs)", [0x22, 0x06, 0x31, 0x40, 0x1B,
                                          0x40, 0x99]),
    ("22 0631 DEAD       (real + unknown)", [0x22, 0x06, 0x31, 0xDE, 0xAD]),
    ("31 03 0203         (routine results)", [0x31, 0x03, 0x02, 0x03]),
    ("31 03 DEAD         (routine results)", [0x31, 0x03, 0xDE, 0xAD]),
    ("23 44 000DE278 04  (ReadMemoryByAddress)", [0x23, 0x44, 0x00, 0x0D,
                                                  0xE2, 0x78, 0x04]),
    ("23                 (bare)", [0x23]),
]


def open_sock():
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((IFACE,))
    s.settimeout(0.05)
    return s


def send(s, cid, data):
    d = bytes(data) + b"\x00" * (8 - len(data))
    s.send(struct.pack("=IB3x8s", cid, 8, d))


def hard_drain(s, max_s=1.2):
    """Drain aggressively and report whether anything from the ECU was pending
    -- a non-empty drain before a probe means the PREVIOUS probe left state."""
    t0, stale = time.time(), []
    while time.time() - t0 < max_s:
        try:
            f = s.recv(16)
        except socket.timeout:
            continue
        cid, dlc, data = struct.unpack("=IB3x8s", f)
        if (cid & 0x7FF) == ECU:
            stale.append(data[:dlc].hex().upper())
    return stale


def collect_raw(s, timeout=1.0):
    out, t0 = [], time.time()
    while time.time() - t0 < timeout:
        try:
            f = s.recv(16)
        except socket.timeout:
            continue
        cid, dlc, data = struct.unpack("=IB3x8s", f)
        if (cid & 0x7FF) == ECU:
            out.append(data[:dlc])
    return out


def decode(d):
    """Plain-language description of one ISO-TP frame. No verdicts."""
    pci = d[0] >> 4
    if pci == 0:
        n = d[0] & 0x0F
        body = d[1:1 + n]
        if body and body[0] == 0x7F:
            return "SF  negative: SID 0x%02X NRC 0x%02X" % (
                body[1] if len(body) > 1 else 0,
                body[2] if len(body) > 2 else 0)
        if body:
            return "SF  positive: SID 0x%02X  %s" % (body[0],
                                                     body[1:].hex().upper())
        return "SF  empty"
    if pci == 1:
        total = ((d[0] & 0x0F) << 8) | d[1]
        return "FF  first frame, total=%d, starts SID 0x%02X" % (total, d[2])
    if pci == 2:
        return "CF  consecutive frame seq=%d  <-- STALE if unexpected" % (
            d[0] & 0x0F)
    if pci == 3:
        return "FC  flow control"
    return "??"


def main():
    s = open_sock()
    print("waking...")
    for _ in range(25):
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.2)
    hard_drain(s)

    for label, body in PROBES:
        print("\n" + "=" * 66)
        print("PROBE: %s" % label)
        stale = hard_drain(s, 0.8)
        if stale:
            print("  !! %d STALE ECU frame(s) pending BEFORE this probe: %s"
                  % (len(stale), stale[:4]))
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.08)
        hard_drain(s, 0.3)

        send(s, TESTER, [len(body)] + list(body))
        frames = collect_raw(s, 1.0)
        if not frames:
            print("  (no 72E frames)")
            continue
        for d in frames:
            print("  72E  %-23s  %s" % (d.hex().upper(), decode(d)))
        # complete any multi-frame so the NEXT probe starts clean
        if frames and frames[0][0] >> 4 == 1:
            print("  -> sending flow control to complete the transfer")
            send(s, TESTER, [0x30, 0x00, 0x00])
            time.sleep(0.3)
            more = collect_raw(s, 0.6)
            for d in more:
                print("  72E  %-23s  %s" % (d.hex().upper(), decode(d)))


if __name__ == "__main__":
    main()
