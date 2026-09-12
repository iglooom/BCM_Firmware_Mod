#!/usr/bin/env python3
"""quietprobe - find out WHY a functional CommunicationControl did not silence
the bus, instead of guessing.

Background.  bcmflash's --quiet-bus sends three functionally-addressed requests
(10 03, 85 02, 28 03 01) with the suppressPosRspMsgIndication bit SET, so no
module answers - not even to reject.  On the car the bus stayed noisy, and a
unanimous "7F 28 22 conditionsNotCorrect" is byte-for-byte indistinguishable
from "every module accepted and went quiet" when nobody is allowed to reply.
This tool exists to remove that blindness.

What it does differently:

  1. CLEARS the suppress bit, so every module's positive response or NRC is
     visible.  THIS IS THE WHOLE POINT - the NRC names the mechanism (rule 35:
     read the NRC, don't just note the failure).
  2. Listens on a RAW CAN socket, not ISO-TP.  A functional request is answered
     by EVERY module at once; a socket bound to one rx ID cannot see that storm.
  3. Measures traffic BEFORE, DURING and AFTER, per CAN ID, and prints the raw
     per-ID counts.  "The bus is quiet" is a claim about numbers, not a feeling.
  4. Runs a BASELINE first and an AFTER window last (rules 29/40: the null
     control belongs on BOTH sides of the stimulus).  If the baseline is already
     silent the run is reported INCONCLUSIVE rather than as a success - an empty
     instrument reading is not a negative verdict (rule 27).
  5. Sweeps the communicationType and, optionally, several functional IDs,
     because both are assumptions this project has never verified against a
     capture of THIS vehicle.

It is a diagnostic: it never flashes anything.  It does send CommunicationControl,
which is network-wide, so it always restores (28 00 01 + 85 01) and additionally
tells you that S3 (~5 s without TesterPresent) restores traffic by itself.

Usage:
    python3 work/flash/quietprobe.py listen                  # baseline only, sends NOTHING
    python3 work/flash/quietprobe.py probe                   # the real experiment
    python3 work/flash/quietprobe.py probe --comm-types 1,2,3
    python3 work/flash/quietprobe.py probe --ids 0x7DF,0x7E0
"""
import argparse
import collections
import socket
import struct
import sys
import time

CAN_FRAME_FMT = "=IB3x8s"
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)
CAN_EFF_FLAG = 0x80000000
CAN_SFF_MASK = 0x000007FF

NRC = {0x10: "generalReject", 0x11: "serviceNotSupported",
       0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLength",
       0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
       0x24: "requestSequenceError", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x35: "invalidKey",
       0x36: "exceedNumberOfAttempts", 0x72: "generalProgrammingFailure",
       0x78: "responsePending", 0x7E: "svcNotSupportedInSession",
       0x7F: "svcNotSupportedInActiveSession"}

COMM_TYPE = {0x01: "normal messages",
             0x02: "network management messages",
             0x03: "normal + network management"}


def open_raw(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def frame(can_id, payload):
    d = bytes(payload)
    return struct.pack(CAN_FRAME_FMT, can_id, 8, d.ljust(8, b"\x00"))


def sf(payload):
    """ISO-TP single frame."""
    p = bytes(payload)
    assert len(p) <= 7
    return bytes([len(p)]) + p


def sniff(sock, seconds, exclude=()):
    """Collect frames for `seconds`.  Returns (per-id Counter, total, samples).

    `exclude` drops our own tester IDs so we never count our own stimulus as
    bus traffic (the probe measuring its own output - rule 33).
    """
    counts = collections.Counter()
    samples = {}
    total = 0
    end = time.time() + seconds
    sock.settimeout(0.2)
    while time.time() < end:
        try:
            data = sock.recv(CAN_FRAME_SIZE)
        except socket.timeout:
            continue
        cid, dlc, payload = struct.unpack(CAN_FRAME_FMT, data)
        cid &= CAN_SFF_MASK if not (cid & CAN_EFF_FLAG) else 0x1FFFFFFF
        if cid in exclude:
            continue
        counts[cid] += 1
        total += 1
        samples.setdefault(cid, payload[:dlc])
    return counts, total, samples


def collect_responses(sock, seconds, req_ids, sid):
    """Gather UDS responses to service `sid` (positive 0x40+sid, or 7F sid xx).

    ⚠ FILTERING ON THE ISO-TP PCI ALONE IS NOT ENOUGH.  An ordinary application
    frame like 030#8000E180A000B307 has first nibble 0, so a PCI-only filter
    classifies it as a single frame and prints it as a "positive response" -
    measured on a live bus, that produced ~100 fabricated responses per window
    and buried the one real NRC.  The reply must therefore be matched against
    the service we actually sent:

        positive:  first byte == sid + 0x40
        negative:  7F <sid> <nrc>

    Anything else is bus traffic, not an answer to us.  (Rule 9: coverage is not
    agreement - "some frame arrived" proves nothing.)
    """
    out = []
    end = time.time() + seconds
    sock.settimeout(0.2)
    while time.time() < end:
        try:
            data = sock.recv(CAN_FRAME_SIZE)
        except socket.timeout:
            continue
        cid, dlc, payload = struct.unpack(CAN_FRAME_FMT, data)
        cid &= CAN_SFF_MASK
        if cid in req_ids:
            continue
        p = payload[:dlc]
        if len(p) < 2 or (p[0] >> 4) != 0:       # single frames only
            continue
        n = p[0] & 0x0F
        body = p[1:1 + n]
        if len(body) < n or not body:
            continue
        is_pos = body[0] == (sid + 0x40)
        is_neg = body[0] == 0x7F and len(body) >= 3 and body[1] == sid
        if is_pos or is_neg:
            out.append((cid, body))
    return out


def describe_response(body):
    if body[0] == 0x7F and len(body) >= 3:
        return "NRC 7F %02X %02X  %s" % (body[1], body[2],
                                         NRC.get(body[2], "?"))
    return "POS %s" % body.hex().upper()


def show_counts(label, counts, total, seconds, samples=None):
    print("   %-18s %5d frames  %6.1f f/s  %3d distinct IDs"
          % (label, total, total / seconds if seconds else 0, len(counts)))
    for cid, n in counts.most_common(12):
        s = ""
        if samples and cid in samples:
            s = "  " + samples[cid].hex().upper()
        print("        %03X  %5d%s" % (cid, n, s))
    if len(counts) > 12:
        print("        ... %d more IDs" % (len(counts) - 12))


def do_listen(a):
    sock = open_raw(a.iface)
    print("== baseline: listening %.1f s on %s, sending NOTHING ==" % (a.window, a.iface))
    counts, total, samples = sniff(sock, a.window, exclude=set(a.ids))
    show_counts("baseline", counts, total, a.window, samples)
    if total == 0:
        print("\n   INCONCLUSIVE: the bus is already silent.  Nothing to quieten,")
        print("   and no positive control is possible.  Wake the network (ignition")
        print("   on) before drawing any conclusion about --quiet-bus.")
    sock.close()


def do_probe(a):
    ids = list(a.ids)
    req_ids = set(ids)
    sock = open_raw(a.iface)

    print("== 0. baseline (no stimulus) ==")
    base_counts, base_total, base_samples = sniff(sock, a.window, exclude=req_ids)
    show_counts("baseline", base_counts, base_total, a.window, base_samples)
    if base_total == 0:
        print("\n   !! INCONCLUSIVE - bus already silent; every 'quiet' result below")
        print("      would be meaningless.  Turn the ignition on and re-run.")
        if not a.force:
            sock.close()
            return
    print()

    results = []
    try:
        for fid in ids:
            for ct in a.comm_types:
                print("== functional %03X, communicationType %02X (%s) =="
                      % (fid, ct, COMM_TYPE.get(ct, "?")))

                # --- 10 03, suppress bit CLEAR so we can read the answers -----
                sock.send(frame(fid, sf([0x10, 0x03])))
                rs = collect_responses(sock, 0.5, req_ids, 0x10)
                print("   10 03 extendedSession -> %d responder(s)" % len(rs))
                for cid, body in rs:
                    print("        %03X  %s" % (cid, describe_response(body)))

                # --- 85 02 ---------------------------------------------------
                sock.send(frame(fid, sf([0x85, 0x02])))
                rs = collect_responses(sock, 0.5, req_ids, 0x85)
                print("   85 02 DTC off        -> %d responder(s)" % len(rs))
                for cid, body in rs:
                    print("        %03X  %s" % (cid, describe_response(body)))

                # --- 28 03 <ct> : the one that is supposed to silence ---------
                sock.send(frame(fid, sf([0x28, 0x03, ct])))
                rs = collect_responses(sock, 0.5, req_ids, 0x28)
                pos = [(c, b) for c, b in rs if b and b[0] == 0x68]
                neg = [(c, b) for c, b in rs if b and b[0] == 0x7F]
                print("   28 03 %02X disableRxTx -> %d responder(s)  (%d accept, %d reject)"
                      % (ct, len(rs), len(pos), len(neg)))
                for cid, body in rs:
                    print("        %03X  %s" % (cid, describe_response(body)))

                # --- did the bus actually go quiet? --------------------------
                # TesterPresent is needed or S3 expires mid-measurement.
                t_end = time.time() + a.window
                dur_counts = collections.Counter()
                dur_total = 0
                next_tp = 0.0
                sock.settimeout(0.2)
                while time.time() < t_end:
                    if time.time() >= next_tp:
                        sock.send(frame(fid, sf([0x3E, 0x80])))
                        next_tp = time.time() + 2.0
                    try:
                        data = sock.recv(CAN_FRAME_SIZE)
                    except socket.timeout:
                        continue
                    cid, dlc, payload = struct.unpack(CAN_FRAME_FMT, data)
                    cid &= CAN_SFF_MASK
                    if cid in req_ids:
                        continue
                    dur_counts[cid] += 1
                    dur_total += 1

                show_counts("during", dur_counts, dur_total, a.window)
                drop = (100.0 * (base_total - dur_total) / base_total
                        if base_total else 0.0)
                silenced = sorted(set(base_counts) - set(dur_counts))
                print("   -> %.1f%% fewer frames; %d of %d IDs stopped"
                      % (drop, len(silenced), len(base_counts)))
                if silenced:
                    print("      stopped: %s"
                          % " ".join("%03X" % c for c in silenced[:16]))
                results.append((fid, ct, len(pos), len(neg), drop, len(silenced)))

                # restore before the next condition (rule 29: reset state
                # between conditions, or the next one inherits this one)
                sock.send(frame(fid, sf([0x28, 0x00, ct])))
                time.sleep(0.1)
                sock.send(frame(fid, sf([0x85, 0x01])))
                time.sleep(a.settle)
                print()
    finally:
        print("== restoring ==")
        for fid in ids:
            for ct in a.comm_types:
                sock.send(frame(fid, sf([0x28, 0x00, ct])))
                time.sleep(0.05)
            sock.send(frame(fid, sf([0x85, 0x01])))
            time.sleep(0.05)
        print("   sent 28 00 xx + 85 01 on %s" % ", ".join("%03X" % i for i in ids))
        print("   (traffic also returns on its own ~5 s after the last 3E 80)")

    print("\n== after (null control on the far side of the stimulus) ==")
    aft_counts, aft_total, _ = sniff(sock, a.window, exclude=req_ids)
    show_counts("after", aft_counts, aft_total, a.window)
    if base_total and aft_total < base_total * 0.5:
        print("   !! the bus did NOT come back to baseline - check the vehicle")

    print("\n== summary ==")
    print("   %-6s %-5s %-8s %-8s %-10s %s"
          % ("ID", "type", "accept", "reject", "drop", "IDs stopped"))
    for fid, ct, pos, neg, drop, ns in results:
        print("   %03X    %02X    %-8d %-8d %-10.1f %d"
              % (fid, ct, pos, neg, drop, ns))
    print("\n   A row with accept=0 reject=0 means NOBODY ANSWERED: either the")
    print("   functional ID is wrong for this bus, or the modules do not accept")
    print("   functional CommunicationControl at all.  A row with reject>0 names")
    print("   the reason in the NRC above - read it before changing anything.")
    sock.close()


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("listen", "probe"):
        s = sub.add_parser(name)
        s.add_argument("--iface", default="can0")
        s.add_argument("--window", type=float, default=3.0,
                       help="measurement window in seconds (default 3)")
        s.add_argument("--ids", default="0x7DF",
                       type=lambda v: [int(x, 0) for x in v.split(",")],
                       help="functional IDs to try, comma separated")
        if name == "probe":
            s.add_argument("--comm-types", dest="comm_types", default="1",
                           type=lambda v: [int(x, 0) for x in v.split(",")],
                           help="communicationType values to sweep (1=normal, "
                                "2=NM, 3=both).  Default 1")
            s.add_argument("--settle", type=float, default=1.0,
                           help="pause between conditions (default 1 s)")
            s.add_argument("--force", action="store_true",
                           help="probe even if the baseline is silent")
    a = ap.parse_args()
    {"listen": do_listen, "probe": do_probe}[a.cmd](a)


if __name__ == "__main__":
    main()
