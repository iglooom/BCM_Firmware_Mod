#!/usr/bin/env python3
"""Operator client for the remote-start TRIGGER service (vehicle test).

    python3 305_rs_trigger.py accept     # controls -- RUN THIS FIRST
    python3 305_rs_trigger.py config     # read the remote-start settings DIDs
    python3 305_rs_trigger.py state      # peek the state cells (no writes)
    python3 305_rs_trigger.py fire 1     # depth 1  (arm the state machine)
    python3 305_rs_trigger.py fire 2     # depth 2  (synthesise RKE enum 8)
    python3 305_rs_trigger.py fire 3     # depth 3  (force power_mode = 4)

⚠ `fire` STARTS AN ENGINE if it works.  Vehicle in PARK, open air, parking
  brake set, nobody under the bonnet.  docs/rs_trigger_design.md Sec.1.

⚠ There is NO abort DID by operator choice -- end a remote start with
  ignition-on or key-off.  Confirm you can do that BEFORE firing.

Use shallow -> deep: depth 1, then 2, then 3.  A null at a shallow depth that
succeeds deeper LOCALISES the blocker, which is the point of three depths.
"""
import os
import sys
import time
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "..", "bench")
sys.path.insert(0, BENCH)

from peeklib import Peeker  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "did_read_mod", os.path.join(BENCH, "293_did_read.py"))
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
read_did = _m.read_did

DEPTH_DID = {1: 0xDE13, 2: 0xDE16, 3: 0xDE2C, 4: 0xDE38, 5: 0xDE4A}
DEPTH_DESC = {
    1: "arm the state machine (lock_request_input=1, DAT_40008D75=1)",
    2: "synthesise RKE enum 8 (rke_command_code=0x1808, flag=1) -- BROKEN,"
       " kept as the contrast arm: flag=1 is bit index 7, read by nobody",
    3: "FORCE power_mode=4 + dirty flags  -- bypasses BCM interlocks",
    4: "sub-state=1 + flag@0x400095E1=1 -> FUN_000AD97C raises bit 27 ITSELF",
    5: "enum 8 ANNOUNCED PROPERLY: 0x40003F53=0xFF then code=0x1808,"
       " in the receive path's own order (0x05856A then 0x05856E)",
}

# state cells worth watching (docs/bench_session_4.md Sec.8.3)
STATE = [
    (0x40001D84, "power_mode word (d2 of 0x80 mirrors byte +1)"),
    (0x40009680, "gate field, preferred base  -- expect (>>27)&7 == 7"),
    (0x4000967C, "sub-state word -- depth 4 sets bits[26:27] to 1"),
    (0x400095E0, "minutes byte +4 | flag byte +5 (depth 4 sets +5)"),
    (0x40002DA0, "rke_command_code word"),
    (0x40008D2C, "lock_request_input"),
]
SETTINGS = [(0xEEFA, "EEFA"), (0xEEFB, "EEFB"), (0xEEFD, "EEFD"),
            (0xEEAB, "EEAB = bit25 of the packed config word")]

PEEK_TRUTH = (0x000DE278, bytes([0x70, 0xE8, 0xE0, 0x00]))


def peek32(p, addr):
    ok, val = read_did(p, 0xDEAD, extra=[(addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
                                         (addr >> 8) & 0xFF, addr & 0xFF])
    if ok and len(bytes(val)) >= 4:
        return bytes(val)[-4:]
    return None


def cmd_accept(p):
    print("=" * 70)
    print("ACCEPTANCE -- every later reading is void if any of these fails")
    print("=" * 70)
    bad = 0
    ok, val = read_did(p, 0xF188)
    good = ok and b"JV6T" in bytes(val)
    print("  C1 F188 part number        : %s" % ("PASS" if good else "FAIL"))
    bad += not good

    v = peek32(p, PEEK_TRUTH[0])
    good = v == PEEK_TRUTH[1]
    print("  C2 peek known-truth 0xDE278: %s  %s"
          % (v.hex().upper() if v else "none", "PASS" if good else "FAIL"))
    bad += not good

    ok, _ = read_did(p, 0x0631)
    print("  C3 stock DID 0x0631 served : %s" % ("PASS" if ok else "FAIL"))
    bad += not ok

    # the trigger DIDs must now ANSWER (they were NRC 0x31 on stock)
    for dep, did in DEPTH_DID.items():
        pass   # deliberately NOT fired here -- firing is never part of accept
    print("  C4 trigger DIDs not fired during accept (by design)")

    print()
    print("  RESULT: %s" % ("ALL PASS" if not bad else "%d FAILED" % bad))
    return 1 if bad else 0


def cmd_config(p):
    print("=" * 70)
    print("REMOTE-START SETTINGS (read-only)")
    print("=" * 70)
    for did, name in SETTINGS:
        ok, val = read_did(p, did)
        print("  %-42s %s" % (name, bytes(val).hex().upper() if ok else val))
    print()
    print("  ⚠ On bench #1 these were EEFA=07 EEFB=04 EEFD=00 EEAB=00.")
    print("    If this vehicle matches, remote start may be configured OFF")
    print("    and NO trigger depth will work (design doc Sec.8).")


def cmd_state(p):
    print("=" * 70)
    print("STATE CELLS (read-only)")
    print("=" * 70)
    for addr, desc in STATE:
        v = peek32(p, addr)
        extra = ""
        if addr in (0x40009680, 0x40009668) and v:
            w = int.from_bytes(v, "big")
            extra = "   (>>27)&7 = %d %s" % ((w >> 27) & 7,
                                             "<-- GATE OPEN" if ((w >> 27) & 7) == 7 else "")
        print("  0x%08X %-46s %s%s"
              % (addr, desc, v.hex().upper() if v else "----", extra))


def raw_22(p, did, timeout=1.5):
    """Send `22 <did>` and return the RAW reply, with NO DID-echo check.

    read_did() requires the echoed DID to match the request.  That is correct
    for stock DIDs and WRONG for our trigger DIDs, whose echo is corrupted by
    the r5 defect -- it turned a working trigger into "no response".
    """
    import socket
    import struct
    from peeklib import TESTER, ECU, NRC
    body = [0x22, (did >> 8) & 0xFF, did & 0xFF]
    with p._lock:
        p._drain(0.05)
        p._send(TESTER, [len(body)] + body)
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                f = p.sock.recv(16)
            except socket.timeout:
                continue
            cid, dlc, data = struct.unpack("=IB3x8s", f)
            if (cid & 0x7FF) != ECU:
                continue
            d = data[:dlc]
            if (d[0] >> 4) != 0:
                continue
            r = bytes(d[1:1 + (d[0] & 0x0F)])
            if not r:
                continue
            if r[0] == 0x7F:
                nrc = r[2] if len(r) > 2 else 0
                if nrc == 0x78:
                    t0 = time.time()
                    continue
                return False, "NRC 0x%02X %s" % (nrc, NRC.get(nrc, "?"))
            return True, r
    return False, "no response"


def cmd_fire(p, depth):
    did = DEPTH_DID[depth]
    print("=" * 70)
    print("FIRE depth %d  (DID 0x%04X)" % (depth, did))
    print("  %s" % DEPTH_DESC[depth])
    print("=" * 70)
    if depth == 3:
        print("  ⚠ Depth 3 bypasses the BCM's own interlocks.  Only the PCM's")
        print("    remain.  Use it only after 1 and 2 are refuted.")
    print()
    print("  state BEFORE:")
    cmd_state(p)

    # ⚠ The cave's DID ECHO IS CORRUPTED -- known defect, see below.  Do NOT
    # use read_did() here: it rejects any reply whose echoed DID != requested
    # DID, so a WORKING trigger reads as "no response" and the operator is
    # told nothing happened when the stores DID execute.
    #
    # Cause (confirmed on the wire): the cave carries the MAGIC in r5 across
    # e_bl calls to the response-append accessor.  r5 is a VOLATILE register
    # (PPC EABI r3-r12), so the callee clobbers it; the first echo byte (0xDE,
    # computed before any call) is correct and the second is garbage.
    #    22 DE 13  ->  62 DE 29 00     (0x29 = clobbered r5 & 0xFF)
    # peek avoided this by holding its value in a SCRATCH RAM CELL, not a
    # register.  The stores all precede the reply block, so they are unaffected
    # -- this is a reporting defect, not a functional one.
    ok, val = raw_22(p, did)
    print("\n  raw response: %s" % val)
    if not ok:
        print("  -> no reply at all.  Either the build is not flashed or the")
        print("     request never reached the ECU.  Nothing was written.")
        return 1
    b = bytes(val)
    if len(b) >= 2 and b[0] == 0x62 and b[1] == ((did >> 8) & 0xFF):
        print("  -> SERVED (echo byte 2 is corrupt by the known r5 defect)")
    else:
        print("  -> UNEXPECTED reply shape; treat as inconclusive")

    for wait in (0.2, 1.0, 3.0):
        time.sleep(wait)
        print("\n  state after %.1fs:" % wait)
        cmd_state(p)
    print()
    print("  Record: 0x80 d2 on the wire, whether the engine cranked, and the")
    print("  two gate-field readings (they settle the Sec.8.1 base ambiguity).")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    with Peeker() as p:
        p.wake()
        if cmd == "accept":
            return cmd_accept(p)
        if cmd == "config":
            return cmd_config(p) or 0
        if cmd == "state":
            return cmd_state(p) or 0
        if cmd == "fire":
            # ⚠ Derive the valid set from DEPTH_DID, never hard-code it.  This
            # validator said ("1","2","3") while DEPTH_DID already had depth 4,
            # so `fire 4` printed a usage message and did nothing (AGENTS.md
            # rule 50 -- a hand-copied expectation going stale, fourth instance
            # in this build cycle).
            valid = {str(d) for d in sorted(DEPTH_DID)}
            if len(sys.argv) < 3 or sys.argv[2] not in valid:
                print("usage: fire {%s}" % "|".join(sorted(valid)))
                return 2
            return cmd_fire(p, int(sys.argv[2]))
    print("unknown command %r" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main())
