#!/usr/bin/env python3
"""Read arbitrary DIDs from the live BCM over UDS 0x22 (read-only).

Written because `did_probe.py` probes a FIXED plan list and silently ignores any
DID given on the command line -- it reported success for five different arguments
and wrote the same output file each time.  That is an instrument returning a
confident wrong answer; AGENTS.md rule 31 says validate the tool against known
truth before believing a word of it, so this one carries its own control.

Transport discipline is peeklib's (persistent AF_CAN socket, BOUNDED drain,
keepalive thread, reply matched against the DID echo) -- docs/peek_tool.md §4.2.

CONTROL: reads F188 (application part number) first.  Its correct answer is known
independently -- `bcmflash.py ident` prints JV6T-14C094-AD -- so if F188 does not
come back as that ASCII string, this reader is broken and every other row is void.

Usage:  python3 work/bench/293_did_read.py EEFA EEFB EEFD
"""
import os
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from peeklib import Peeker, NRC, TESTER, ECU  # noqa: E402

CONTROL_DID = 0xF188
CONTROL_EXPECT = b"JV6T-14C094-AD"


def read_did(p, did, timeout=1.2, extra=None):
    """Single-DID 0x22.  Returns (ok, bytes) or (False, reason).

    `extra` appends further request bytes -- needed for services whose
    payload rides as additional synthetic DIDs (e.g. peek's address).
    """
    body = [0x22, (did >> 8) & 0xFF, did & 0xFF] + list(extra or [])
    with p._lock:
        p._drain(0.05)
        p._send(TESTER, [len(body)] + body)
        t0 = time.time()
        pend = 0
        while time.time() - t0 < timeout:
            try:
                f = p.sock.recv(16)
            except socket.timeout:
                continue
            cid, dlc, data = struct.unpack("=IB3x8s", f)
            if (cid & 0x7FF) != ECU:
                continue
            d = data[:dlc]
            pci = d[0] >> 4
            if pci == 0:
                n = d[0] & 0x0F
                r = bytes(d[1:1 + n])
            elif pci == 1:
                total = ((d[0] & 0x0F) << 8) | d[1]
                r = bytearray(d[2:8])
                p._send(TESTER, [0x30, 0x00, 0x00])
                while len(r) < total and time.time() - t0 < timeout:
                    try:
                        g = p.sock.recv(16)
                    except socket.timeout:
                        continue
                    gid, gdlc, gdata = struct.unpack("=IB3x8s", g)
                    if (gid & 0x7FF) != ECU or (gdata[0] >> 4) != 2:
                        continue
                    r += gdata[1:8]
                r = bytes(r[:total])
            else:
                continue
            if not r:
                continue
            if r[0] == 0x7F:
                nrc = r[2] if len(r) > 2 else 0
                if nrc == 0x78 and pend < 20:      # responsePending
                    pend += 1
                    t0 = time.time()
                    continue
                return False, "NRC 0x%02X %s" % (nrc, NRC.get(nrc, "?"))
            if r[0] != 0x62 or len(r) < 3:
                continue
            if ((r[1] << 8) | r[2]) != did:
                continue                            # stale / other DID
            return True, r[3:]
    return False, "no response"


def show(did, ok, res):
    if not ok:
        print("  %04X : %s" % (did, res))
        return
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in res)
    print("  %04X : %-26s |%s|  (%d byte%s)"
          % (did, res.hex(" ").upper() or "<empty>", txt,
             len(res), "" if len(res) == 1 else "s"))


def main():
    dids = [int(x, 16) for x in sys.argv[1:]] or [0xEEFA, 0xEEFB, 0xEEFD]
    with Peeker() as p:
        p.assert_live()
        print("peek controls OK -- transport sound\n")

        ok, res = read_did(p, CONTROL_DID)
        print("CONTROL (known truth):")
        show(CONTROL_DID, ok, res)
        good = ok and CONTROL_EXPECT in bytes(res)
        print("  -> %s\n" % ("PASS" if good else
                             "FAIL: expected %s -- ALL ROWS BELOW ARE VOID"
                             % CONTROL_EXPECT.decode()))

        for did in dids:
            ok, res = read_did(p, did)
            show(did, ok, res)

        if not good:
            print("\n⚠ CONTROL FAILED -- do not use these values (rule 27).")


# ⚠ MUST be guarded: this module is imported by 302_stock_did_probe.py and
# 305_rs_trigger.py for its read_did().  Unguarded, the import ran main(),
# which (a) crashed the importer by parsing ITS argv as hex DIDs, and (b)
# silently performed a real bus probe as an import side effect.
if __name__ == "__main__":
    main()
