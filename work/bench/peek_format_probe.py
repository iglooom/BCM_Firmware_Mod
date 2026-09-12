#!/usr/bin/env python3
"""FALSIFIER: does the stock 0x22 handler tolerate EXTRA request bytes?

The peek design (docs/uds_peek_design.md 3.1) proposes the wire format

    22 <DIDhi> <DIDlo> <A3> <A2> <A1> <A0>      -> 62 <DID> <bytes at A3A2A1A0>

i.e. a 7-byte UDS request where stock sends 3.  That fits a single CAN frame
exactly (PCI 0x07 + 7 bytes = 8).  But if the STOCK application length-checks
the request and answers 7F 22 13 incorrectMessageLength, the carrier is wrong
and the cave needs a different one (0x31 RoutineControl, or a dedicated SID).

This is testable on STOCK firmware with no patch and no flash: send the same
DID with 3 bytes and with 7 bytes and compare.

READ-ONLY on the ECU: only ordinary 0x22 ReadDataByIdentifier requests.

Controls (AGENTS.md rule 27 -- an empty instrument reading is INCONCLUSIVE,
never a negative verdict about the subject):
  * a liveness probe must answer before any trial is recorded;
  * the 3-byte baseline must answer for each DID, or the 7-byte result for that
    DID is reported INCONCLUSIVE rather than "rejected";
  * every trial is repeated, so a single dropped frame cannot decide anything.

Usage: python3 work/bench/peek_format_probe.py
"""
import json
import os
import socket
import struct
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
OUT = os.path.join(ROOT, "work/bench/logs/peek_format_probe.json")
IFACE = "can0"
TESTER = 0x726
ECU = 0x72E

NRC = {0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
       0x13: "incorrectMessageLength", 0x22: "conditionsNotCorrect",
       0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
       0x78: "responsePending",
       0x7E: "svcNotSupportedInSession", 0x7F: "svcNotSupportedInSession"}

# DIDs proven SERVED on this bench unit, 1 byte each (live_debug_uds.md 8.5)
DIDS = [0x0631, 0x401B, 0x4099, 0x40BE, 0x4125]


def open_sock():
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((IFACE,))
    s.settimeout(0.05)
    return s


def send(s, can_id, data):
    d = bytes(data) + b"\x00" * (8 - len(data))
    s.send(struct.pack("=IB3x8s", can_id, 8, d))


def drain(s, max_s=0.25):
    """Discard pending frames.

    MUST be time-bounded: once awake the BCM transmits 0x030/0x0C8/... every few
    ms, so an "until timeout" drain never returns on a live bus.  That bug made
    the first run of this script look like a dead ECU.
    """
    t0 = time.time()
    while time.time() - t0 < max_s:
        try:
            s.recv(16)
        except socket.timeout:
            return


def collect(s, timeout=0.7):
    """Return every 0x72E payload seen within the window."""
    out, t0 = [], time.time()
    while time.time() - t0 < timeout:
        try:
            frame = s.recv(16)
        except socket.timeout:
            continue
        cid, dlc, data = struct.unpack("=IB3x8s", frame)
        if (cid & 0x7FF) == ECU:
            out.append(data[:dlc])
    return out


def parse(frames):
    """Classify the first meaningful single-frame reply."""
    for d in frames:
        if not d:
            continue
        pci = d[0] >> 4
        if pci == 0:                       # single frame
            n = d[0] & 0x0F
            body = d[1:1 + n]
            if not body:
                continue
            if body[0] == 0x62:
                return dict(kind="POSITIVE", sid=0x62,
                            did="0x%04X" % ((body[1] << 8) | body[2])
                            if len(body) >= 3 else None,
                            payload=body[3:].hex().upper(),
                            nbytes=max(0, len(body) - 3), raw=d.hex().upper())
            if body[0] == 0x7F:
                nrc = body[2] if len(body) > 2 else 0
                if nrc == 0x78:            # responsePending -- keep looking
                    continue
                return dict(kind="NEGATIVE", nrc="0x%02X" % nrc,
                            nrc_name=NRC.get(nrc, "?"), raw=d.hex().upper())
        elif pci == 1:                     # first frame of a multi-frame reply
            total = ((d[0] & 0x0F) << 8) | d[1]
            return dict(kind="POSITIVE_MF", nbytes=total - 3,
                        payload=d[5:].hex().upper(), raw=d.hex().upper())
    return dict(kind="NO_RESPONSE")


def wake(s):
    """Wake the BCM.  Measured on this bench: ~3 s of keepalive is NOT enough;
    4 s at 5 Hz reliably brings it up (a manual 20 x 0.2 s run answered, a
    12 x 0.25 s run did not)."""
    for _ in range(25):
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.2)
    drain(s)


def trial(s, req_body, reps=3):
    """Send a UDS request body (PCI computed) reps times; return results.

    A multi-frame reply (first frame, PCI 0x1x) needs a flow-control frame or
    the ECU stalls and the NEXT trial sees a stale/absent bus.  We send FC
    (30 00 00) and then drain the consecutive frames -- we only need the FIRST
    frame to classify, not the whole payload.
    """
    got = []
    for _ in range(reps):
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.05)
        drain(s, 0.1)
        send(s, TESTER, [len(req_body)] + list(req_body))
        frames = collect(s)
        r = parse(frames)
        if r["kind"] == "POSITIVE_MF":
            send(s, TESTER, [0x30, 0x00, 0x00])   # flow control: clear to send
            time.sleep(0.15)
            drain(s, 0.2)
        got.append(r)
        time.sleep(0.12)
    return got


def summarise(rs):
    kinds = [r["kind"] for r in rs]
    for r in rs:
        if r["kind"].startswith("POSITIVE"):
            return "POSITIVE", r
        if r["kind"] == "NEGATIVE":
            return "NEGATIVE %s %s" % (r["nrc"], r["nrc_name"]), r
    return "NO_RESPONSE", rs[0]


def main():
    s = open_sock()
    res = {"iface": IFACE, "dids": [], "note": "stock firmware, read-only"}

    print("waking the BCM (first request after idle is always dropped)...")
    wake(s)

    live = trial(s, [0x22, 0xF1, 0x90], reps=3)
    lk, _ = summarise(live)
    print("liveness 22 F190: %s" % lk)
    res["liveness"] = lk
    if lk == "NO_RESPONSE":
        print("\n!! ECU not answering at all -- INCONCLUSIVE, not a negative.")
        print("   (AGENTS.md rule 27: assert the reference channel is alive first)")
        json.dump(res, open(OUT, "w"), indent=1)
        sys.exit(2)

    print("\n== per-DID: 3-byte baseline vs 7-byte extended request ==")
    verdicts = []
    for did in DIDS:
        hi, lo = (did >> 8) & 0xFF, did & 0xFF
        base = trial(s, [0x22, hi, lo])
        bk, brec = summarise(base)
        # 7-byte form: the peek wire format, single CAN frame exactly
        ext = trial(s, [0x22, hi, lo, 0xDE, 0xAD, 0xBE, 0xEF])
        ek, erec = summarise(ext)

        if bk == "NO_RESPONSE":
            verdict = "INCONCLUSIVE (baseline silent)"
        elif ek == "NO_RESPONSE":
            verdict = "IGNORED/DROPPED"
        elif ek.startswith("POSITIVE"):
            verdict = "TOLERATED"
        else:
            verdict = "REJECTED"
        verdicts.append(verdict)

        print("  0x%04X  base=%-28s ext=%-28s -> %s"
              % (did, bk, ek, verdict))
        res["dids"].append(dict(did="0x%04X" % did, baseline=bk, baseline_raw=brec,
                                extended=ek, extended_raw=erec, verdict=verdict))

    print("\n== verdict ==")
    tol = verdicts.count("TOLERATED")
    rej = verdicts.count("REJECTED")
    drop = verdicts.count("IGNORED/DROPPED")
    inc = sum(1 for v in verdicts if v.startswith("INCONCLUSIVE"))
    print("  tolerated %d / rejected %d / dropped %d / inconclusive %d"
          % (tol, rej, drop, inc))
    if inc == len(verdicts):
        overall = "INCONCLUSIVE -- no baseline answered"
    elif tol and not rej and not drop:
        overall = ("FORMAT CONFIRMED: stock 0x22 ignores trailing bytes, "
                   "so 22 <DID> <addr32> is a viable peek carrier")
    elif rej or drop:
        overall = ("FORMAT REFUTED for at least one DID -- stock handler "
                   "length-checks; pick another carrier (0x31, or new SID)")
    else:
        overall = "MIXED -- see per-DID table"
    print("  %s" % overall)
    res["overall"] = overall

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)


if __name__ == "__main__":
    main()
