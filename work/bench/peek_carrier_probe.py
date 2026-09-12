#!/usr/bin/env python3
"""FALSIFIER ROUND 2: pick the peek carrier.

Round 1 (peek_format_probe.py) REFUTED "22 <DID> <addr32>": 5/5 REJECTED with
NRC 0x31 requestOutOfRange -- NOT 0x13 incorrectMessageLength.  That NRC points
at the mechanism visible in FUN_0010B65E's decompile: it LOOPS over the request
reading DID pairs, so 22 0631 DEAD BEEF is parsed as THREE DIDs and refused
because 0xDEAD is not in the identifier array.

So the question is which envelope can carry 32 bits of address:

  C1  MULTI-DID 0x22.  If 3 REAL DIDs in one request are served, then the
      address can ride AS two synthetic DIDs: 22 <MAGIC> <Ahi16> <Alo16>.
      Test: 22 with 2 real DIDs, and with 3 real DIDs.
      Also test a real DID followed by ONE unknown DID, to see whether the
      handler refuses the whole request or serves the known part (that decides
      whether our cave can intercept before the refusal).

  C2  0x31 RoutineControl.  FUN_0010B65E compares 0x31 too, and routines take
      arbitrary request data by design.  Probe what the stock app answers for
      a few routine IDs with start(01)/stop(02)/results(03) -- we are looking
      for the SHAPE of the response (0x71 vs which NRC), not to run anything.
      NRC 0x31 requestOutOfRange for an unknown RID = the service EXISTS and
      parsed our request = a viable carrier.
      NRC 0x11 serviceNotSupported = dead end.

  C3  0x23 ReadMemoryByAddress -- confirm on THIS unit that it is absent
      (expected 0x11), as a baseline for "what a missing service looks like".

READ-ONLY intent: 0x22 reads, 0x23 probe, and 0x31 with routine IDs that are
NOT executed where avoidable.  ROUTINE SAFETY: we only send subfunction 0x03
(requestRoutineResults) for unknown RIDs -- it reads results, it does not start
anything.  We never send 0x01 (start).

Usage: python3 work/bench/peek_carrier_probe.py
"""
import json
import os
import socket
import struct
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
OUT = os.path.join(ROOT, "work/bench/logs/peek_carrier_probe.json")
IFACE = "can0"
TESTER = 0x726
ECU = 0x72E

NRC = {0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
       0x13: "incorrectMessageLength", 0x22: "conditionsNotCorrect",
       0x24: "requestSequenceError", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x72: "generalProgrammingFailure",
       0x78: "responsePending",
       0x7E: "svcNotSupportedInSession", 0x7F: "svcNotSupportedInSession"}

# proven SERVED, 1 byte each, on this bench unit (live_debug_uds.md 8.5)
REAL = [0x0631, 0x401B, 0x4099, 0x40BE, 0x4125]


def open_sock():
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((IFACE,))
    s.settimeout(0.05)
    return s


def send(s, can_id, data):
    d = bytes(data) + b"\x00" * (8 - len(data))
    s.send(struct.pack("=IB3x8s", can_id, 8, d))


def drain(s, max_s=0.2):
    t0 = time.time()
    while time.time() - t0 < max_s:
        try:
            s.recv(16)
        except socket.timeout:
            return


def collect(s, timeout=0.7):
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
    for d in frames:
        if not d:
            continue
        pci = d[0] >> 4
        if pci == 0:
            n = d[0] & 0x0F
            body = d[1:1 + n]
            if not body:
                continue
            if body[0] == 0x7F:
                nrc = body[2] if len(body) > 2 else 0
                if nrc == 0x78:
                    continue
                return dict(kind="NEG", nrc=nrc,
                            nrc_name=NRC.get(nrc, "?"), raw=d.hex().upper())
            if body[0] & 0x40:
                return dict(kind="POS", sid=body[0], nbytes=len(body) - 1,
                            body=body.hex().upper(), raw=d.hex().upper())
        elif pci == 1:
            total = ((d[0] & 0x0F) << 8) | d[1]
            return dict(kind="POS_MF", sid=d[2], total=total,
                        raw=d.hex().upper())
    return dict(kind="NONE")


def wake(s):
    for _ in range(25):
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.2)
    drain(s)


def req(s, body, reps=2, label=""):
    """Send a UDS request (single frame only, body <= 7). Return best result."""
    assert len(body) <= 7, "body too long for a single frame: %d" % len(body)
    best = dict(kind="NONE")
    for _ in range(reps):
        send(s, TESTER, [0x02, 0x3E, 0x80])
        time.sleep(0.05)
        drain(s, 0.1)
        send(s, TESTER, [len(body)] + list(body))
        r = parse(collect(s))
        if r["kind"] == "POS_MF":
            send(s, TESTER, [0x30, 0x00, 0x00])
            time.sleep(0.15)
            drain(s, 0.25)
        if r["kind"] != "NONE":
            best = r
            break
        time.sleep(0.1)
    return best


def show(label, r):
    if r["kind"] == "NEG":
        txt = "NEG 0x%02X %s" % (r["nrc"], r["nrc_name"])
    elif r["kind"] == "POS":
        txt = "POS sid=0x%02X %dB %s" % (r["sid"], r["nbytes"], r["body"])
    elif r["kind"] == "POS_MF":
        txt = "POS(multiframe) sid=0x%02X total=%d" % (r["sid"], r["total"])
    else:
        txt = "no response"
    print("   %-44s %s" % (label, txt))
    return txt


def main():
    s = open_sock()
    res = {"iface": IFACE, "note": "stock firmware"}
    print("waking the BCM...")
    wake(s)
    live = req(s, [0x22, 0xF1, 0x90], reps=3)
    lk = show("liveness 22 F190", live)
    res["liveness"] = lk
    if live["kind"] == "NONE":
        print("\n!! ECU silent -- INCONCLUSIVE (rule 27), not a negative.")
        json.dump(res, open(OUT, "w"), indent=1)
        sys.exit(2)

    # ---------------- C1: multi-DID 0x22 ----------------------------
    print("\n== C1: is MULTI-DID 0x22 supported? ==")
    c1 = {}
    a, b, c = REAL[0], REAL[1], REAL[2]
    c1["1did"] = show("22 %04X                (1 real)" % a,
                      req(s, [0x22, a >> 8, a & 0xFF]))
    c1["2did"] = show("22 %04X %04X           (2 real)" % (a, b),
                      req(s, [0x22, a >> 8, a & 0xFF, b >> 8, b & 0xFF]))
    c1["3did"] = show("22 %04X %04X %04X      (3 real)" % (a, b, c),
                      req(s, [0x22, a >> 8, a & 0xFF, b >> 8, b & 0xFF,
                              c >> 8, c & 0xFF]))
    c1["real_plus_unknown"] = show(
        "22 %04X DEAD           (real + unknown)" % a,
        req(s, [0x22, a >> 8, a & 0xFF, 0xDE, 0xAD]))
    c1["unknown_only"] = show("22 DEAD                (unknown alone)",
                              req(s, [0x22, 0xDE, 0xAD]))
    res["C1_multi_did"] = c1

    # ---------------- C2: 0x31 RoutineControl -----------------------
    print("\n== C2: does 0x31 RoutineControl exist? (subfn 03 = read results) ==")
    print("   (subfunction 0x03 requestRoutineResults only -- never 0x01 start)")
    c2 = {}
    for rid in (0x0203, 0xDEAD, 0xF000):
        c2["rid_%04X" % rid] = show(
            "31 03 %04X             (results, RID %04X)" % (rid, rid),
            req(s, [0x31, 0x03, rid >> 8, rid & 0xFF]))
    # a malformed-length 0x31 tells us whether it length-checks like 0x22 did
    c2["short"] = show("31 03                  (truncated)",
                       req(s, [0x31, 0x03]))
    res["C2_routine"] = c2

    # ---------------- C3: 0x23 baseline -----------------------------
    print("\n== C3: 0x23 ReadMemoryByAddress on this unit (expect 0x11) ==")
    c3 = {}
    c3["addr_len_fmt_44"] = show(
        "23 44 000DE278 04      (fmt 4/4)",
        req(s, [0x23, 0x44, 0x00, 0x0D, 0xE2, 0x78, 0x04]))
    c3["bare"] = show("23                     (bare)", req(s, [0x23]))
    res["C3_readmem"] = c3

    # ---------------- verdict ---------------------------------------
    print("\n== verdict ==")
    lines = []

    def isneg(r, code):
        return r.get("kind") == "NEG" and r.get("nrc") == code

    multi_ok = c1["3did"].startswith("POS")
    if multi_ok:
        lines.append("C1 VIABLE: multi-DID 0x22 is served -> the address can "
                     "ride as two synthetic DIDs (22 MAGIC Ahi Alo).")
    else:
        lines.append("C1 NOT viable: multi-DID 0x22 is not served (%s)."
                     % c1["3did"])

    r31 = None
    for k in ("rid_0203", "rid_DEAD", "rid_F000"):
        if c2[k].startswith("POS") or "0x31" in c2[k] or "0x12" in c2[k] \
                or "0x33" in c2[k] or "0x22" in c2[k] or "0x24" in c2[k]:
            r31 = k
            break
    if c2["rid_DEAD"].startswith("NEG 0x11"):
        lines.append("C2 NOT viable: 0x31 answers serviceNotSupported.")
    elif r31:
        lines.append("C2 VIABLE: 0x31 exists and parses requests (%s = %s) -> "
                     "a routine is the natural arbitrary-data carrier."
                     % (r31, c2[r31]))
    else:
        lines.append("C2 unclear: %s" % c2)

    lines.append("C3 baseline (what an ABSENT service looks like): %s"
                 % c3["addr_len_fmt_44"])

    for ln in lines:
        print("  " + ln)
    res["verdict"] = lines

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)


if __name__ == "__main__":
    main()
