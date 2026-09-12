#!/usr/bin/env python3
"""Probe the 17 candidate DIDs on the BENCH BCM *before* flashing anything.

Why this must run first: the probe bank repoints 17 existing DID readers.  If a
chosen DID is not actually reachable via 0x22 on the application (wrong session,
security-gated, or simply not served), the probe is dead weight - and we would
only discover that AFTER a flash.

This is read-only on the ECU: plain UDS ReadDataByIdentifier requests.

For each DID we record:
    positive response (0x62)  -> served, and we capture the CURRENT bytes
    negative 0x7F ... 0x31    -> requestOutOfRange, NOT served
    negative 0x7F ... 0x33    -> securityAccessDenied (needs 0x27)
    negative 0x7F ... 0x7E/7F -> wrong session
    no response               -> asleep or not served

The CURRENT byte value is itself useful: it is the OEM cell's value, which lets
us sanity-check the length table (a length-1 DID must answer with exactly 1
data byte).

Usage:  python3 work/bench/did_probe.py [--all]
"""
import json
import os
import re
import subprocess
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
PLAN = os.path.join(ROOT, "work/owner/probe_bank_bytes.json")
OUT = os.path.join(ROOT, "work/bench/logs/did_probe_result.json")
IFACE = "can0"
TESTER = "726"
ECU = "72E"

NRC = {0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
       0x13: "incorrectMessageLength", 0x22: "conditionsNotCorrect",
       0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
       0x7E: "svcNotSupportedInSession", 0x7F: "svcNotSupportedInSession"}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def wake():
    """The BCM sleeps; the first request after idle is always dropped."""
    for _ in range(12):
        subprocess.run(["cansend", IFACE, "%s#023E80000000000000" % TESTER],
                       capture_output=True)
        time.sleep(0.25)


def read_did(did, timeout=0.6):
    """Send 22 hi lo, return (raw_hex, parsed) for the first 72E reply."""
    hi, lo = (did >> 8) & 0xFF, did & 0xFF
    p = subprocess.Popen(["candump", "-L", "-T", str(int(timeout * 1000)), IFACE],
                         stdout=subprocess.PIPE, text=True)
    time.sleep(0.12)
    subprocess.run(["cansend", IFACE, "%s#0322%02X%02X00000000" % (TESTER, hi, lo)],
                   capture_output=True)
    try:
        out, _ = p.communicate(timeout=timeout + 1.0)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    for line in out.splitlines():
        m = re.search(r"\s%s#([0-9A-Fa-f]+)" % ECU, line)
        if not m:
            continue
        data = bytes.fromhex(m.group(1))
        if not data:
            continue
        # single frame: [len][62][hi][lo][payload...]
        if data[0] >> 4 == 0 and len(data) > 1:
            n = data[0] & 0x0F
            body = data[1:1 + n]
            if body and body[0] == 0x62:
                return m.group(1), dict(ok=True, did="0x%04X" % did,
                                        payload=body[3:].hex().upper(),
                                        nbytes=len(body) - 3)
            if body and body[0] == 0x7F:
                nrc = body[2] if len(body) > 2 else 0
                return m.group(1), dict(ok=False, did="0x%04X" % did,
                                        nrc="0x%02X" % nrc,
                                        nrc_name=NRC.get(nrc, "?"))
        elif data[0] >> 4 == 1:      # first frame of a multi-frame reply
            total = ((data[0] & 0x0F) << 8) | data[1]
            return m.group(1), dict(ok=True, did="0x%04X" % did,
                                    payload=data[5:].hex().upper(),
                                    nbytes=total - 3, multiframe=True)
    return None, dict(ok=False, did="0x%04X" % did, nrc=None, nrc_name="NO RESPONSE")


def main():
    probes = json.load(open(PLAN))["probes"]
    dids = [(int(p["did"], 16), p["watch"], p["why"]) for p in probes]

    print("waking the BCM (first request after idle is always dropped)...")
    wake()
    raw, r = read_did(0xF190)          # VIN-ish DID as a liveness check
    print("liveness DID 0xF190: %s\n" % ("OK" if r.get("ok") else r.get("nrc_name")))

    served, denied, dead = [], [], []
    print("== probing %d candidate DIDs ==" % len(dids))
    for did, watch, why in dids:
        subprocess.run(["cansend", IFACE, "%s#023E80000000000000" % TESTER],
                       capture_output=True)
        raw, r = read_did(did)
        r["watch"] = watch
        r["why"] = why
        if r.get("ok"):
            served.append(r)
            print("   0x%04X  SERVED   %d byte(s) = %s   (would watch %s)"
                  % (did, r["nbytes"], r["payload"] or "-", watch))
        elif r.get("nrc"):
            denied.append(r)
            print("   0x%04X  NRC %s %s" % (did, r["nrc"], r["nrc_name"]))
        else:
            dead.append(r)
            print("   0x%04X  no response" % did)
        time.sleep(0.15)

    print("\n== summary ==")
    print("   served      : %d" % len(served))
    print("   negative    : %d" % len(denied))
    print("   no response : %d" % len(dead))
    if served:
        ones = [s for s in served if s["nbytes"] == 1]
        print("\n   length-1 replies: %d/%d  (the length table @0x21318 predicts"
              " ALL %d are length 1)" % (len(ones), len(served), len(served)))
        if len(ones) != len(served):
            print("   ⚠ MISMATCH - the length table's prediction is wrong for:")
            for s in served:
                if s["nbytes"] != 1:
                    print("        %s -> %d bytes" % (s["did"], s["nbytes"]))
        else:
            print("   ✓ length table CONFIRMED ON THE WIRE for every served DID")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(dict(served=served, negative=denied, dead=dead), open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)


if __name__ == "__main__":
    main()
