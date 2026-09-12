#!/usr/bin/env python3
"""STEP 2 (MANDATORY, before any VLE is written) -- probe the candidate MAGIC
DIDs on the CURRENTLY FLASHED firmware.

AGENTS.md rule 35: falsify a wire format against the stock target before
building anything for it.  The peek service's original envelope was refuted
5/5 this way, and the NRC identified the mechanism.

WHAT A PASS LOOKS LIKE
  Each candidate MAGIC must currently be REFUSED (NRC 0x31 requestOutOfRange
  is the expected form -- the handler loops over DID pairs and rejects an
  unknown identifier).  If a candidate ANSWERS, it is a live OEM DID that the
  image scan missed, and using it would displace stock behaviour.

CONTROLS (an unanswered probe is meaningless without these -- rule 27):
  C1  a known-good DID (F188) must return the part number.  If the transport
      is dead, every "refused" below is INCONCLUSIVE, not a pass.
  C2  peek's MAGIC 0xDEAD is probed to show whether THIS unit runs the peek
      build.  Reported, never asserted: on a stock unit it is expected to
      fail, and that is fine.

Reuses read_did() from 293_did_read.py rather than inventing a new client --
that function already handles the three instrument bugs in peek_tool.md 4.2
(bounded drain, flow control, single persistent socket).

Read-only: sends only 0x22 requests.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "..", "bench")
sys.path.insert(0, BENCH)

from peeklib import Peeker  # noqa: E402

# read_did lives in a module whose name starts with a digit -> import by path
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "did_read_mod", os.path.join(BENCH, "293_did_read.py"))
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
read_did = _m.read_did

CANDIDATES = [0xDE13, 0xDE16, 0xDE2C, 0xDE38, 0xDE4A, 0xDE4C]
PEEK_MAGIC = 0xDEAD


def fmt(ok, val):
    if ok:
        b = bytes(val)
        return "ANSWERED %s" % b[:12].hex().upper()
    return str(val)


def main():
    with Peeker() as p:
        p.wake()

        print("=" * 72)
        print("CONTROLS")
        print("=" * 72)
        ok, val = read_did(p, 0xF188)
        c1 = ok and b"JV6T" in bytes(val)
        print("  C1 F188 (known good) : %-38s -> %s"
              % (fmt(ok, val), "PASS" if c1 else "FAIL"))
        if not c1:
            print()
            print("  ⚠ TRANSPORT NOT PROVEN ALIVE -> every result below would be")
            print("    INCONCLUSIVE, not a negative (rule 27).  Stopping.")
            return 1

        # C2: peek's MAGIC needs its ADDRESS as two synthetic DIDs -- a bare
        # `22 DEAD` is NOT the peek format and is correctly refused.  Probing
        # the bare DID was this script's own bug: it reported "stock unit" on
        # a unit that demonstrably runs peek (rule 27 -- the instrument, not
        # the subject).  Use the real format: 22 DEAD 000D E278 -> known truth.
        ok, val = read_did(p, 0xDEAD, extra=[0x00, 0x0D, 0xE2, 0x78])
        peek_ok = ok and bytes(val)[-4:] == bytes([0x70, 0xE8, 0xE0, 0x00])
        print("  C2 peek 0x000DE278   : %-38s -> %s"
              % (fmt(ok, val),
                 "peek build present" if peek_ok else "peek not served"))

        print()
        print("=" * 72)
        print("CANDIDATE MAGICS -- each MUST be refused")
        print("=" * 72)
        free = []
        for did in CANDIDATES:
            ok, val = read_did(p, did)
            if not ok:
                free.append(did)
            print("  0x%04X : %-40s -> %s"
                  % (did, fmt(ok, val), "FREE" if not ok else "*** IN USE ***"))

        print()
        print("=" * 72)
        print("VERDICT")
        print("=" * 72)
        print("  free: %s" % ", ".join("0x%04X" % d for d in free))
        if len(free) >= 3:
            print("  PASS -- proposed depth1=0x%04X depth2=0x%04X depth3=0x%04X"
                  % tuple(free[:3]))
            return 0
        print("  FAIL -- need 3 free MAGICs, got %d" % len(free))
        return 1


if __name__ == "__main__":
    sys.exit(main())
