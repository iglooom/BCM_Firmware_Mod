#!/usr/bin/env python3
"""Baseline the probe DIDs *before* flashing, under a known RKE stimulus.

Rationale (and the reason this is not optional): after the flash, each of these
DIDs returns a RAM cell of our choosing.  To recognise a probe as working we
must know what the SAME DID returns on stock firmware under the SAME stimulus.
Otherwise a probe that never changes is ambiguous - unmodified OEM value, or a
correctly-repointed probe on a cell that genuinely does not move?

Also: the OEM values recorded here are the guard rail.  If after flashing a DID
still returns exactly its OEM baseline while the bus shows the watched cell
changing, that probe did not take.

Procedure per DID: poll continuously while driving an RKE press through
rfa_sim.py, and record the value set observed.

Usage: python3 work/bench/did_baseline.py [nibble]
"""
import json
import os
import re
import subprocess
import sys
import time

ROOT = "/home/gl/Projects/ford/BCM/Research"
PLAN = os.path.join(ROOT, "work/owner/probe_bank_bytes.json")
OUT = os.path.join(ROOT, "work/bench/logs/did_baseline.json")
IFACE, TESTER, ECU = "can0", "726", "72E"


def wake():
    for _ in range(10):
        subprocess.run(["cansend", IFACE, "%s#023E80000000000000" % TESTER],
                       capture_output=True)
        time.sleep(0.22)


def read_did(did, to=0.5):
    hi, lo = (did >> 8) & 0xFF, did & 0xFF
    p = subprocess.Popen(["candump", "-L", "-T", str(int(to * 1000)), IFACE],
                         stdout=subprocess.PIPE, text=True)
    time.sleep(0.10)
    subprocess.run(["cansend", IFACE, "%s#0322%02X%02X00000000" % (TESTER, hi, lo)],
                   capture_output=True)
    try:
        out, _ = p.communicate(timeout=to + 1)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
    for line in out.splitlines():
        m = re.search(r"\s%s#([0-9A-Fa-f]+)" % ECU, line)
        if not m:
            continue
        d = bytes.fromhex(m.group(1))
        if d and d[0] >> 4 == 0 and len(d) > 1:
            n = d[0] & 0x0F
            b = d[1:1 + n]
            if b and b[0] == 0x62:
                return b[3:].hex().upper()
    return None


def press(nibble):
    """Fire one RKE press on MS-CAN via the proven simulator.

    ⚠ rfa_sim.py's press mode takes --cmd {lock,unlock,...}, NOT a positional
    nibble.  An earlier version of this file called it as `press <nibble>`,
    which argparse rejected: every press silently failed and the run reported
    "0 DIDs vary" - a clean-looking but completely uncontrolled result
    (AGENTS.md rule 8).  The launcher is now checked and its exit status is
    surfaced by verify_stimulus() below.
    """
    cmd = {1: "lock", 2: "unlock"}.get(nibble)
    if cmd is None:
        # rfa_sim.CMDS only defines idle/lock/unlock; nibble 3 (the d3=06
        # command) has no name there, so baseline it with the sweep path.
        raise SystemExit("nibble %d has no rfa_sim --cmd name; use nibble 1 or 2"
                         % nibble)
    return subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "work/bench/rfa_sim.py"),
         "press", "--cmd", cmd, "--n", "3", "--key-outside"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def verify_stimulus(nibble):
    """Run ONE press up-front and prove it reached the bus before baselining.

    Without this the whole run is uncontrolled: if the stimulus never fires,
    every DID trivially reads 'static'.
    """
    print("verifying the stimulus actually fires...")
    before = subprocess.Popen(["candump", "-L", "-T", "6000", "can1"],
                              stdout=subprocess.PIPE, text=True)
    time.sleep(0.3)
    p = press(nibble)
    out, err = p.communicate(timeout=60)
    try:
        cap, _ = before.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        before.kill()
        cap, _ = before.communicate()
    strobes = len([ln for ln in cap.splitlines()
                   if re.search(r"\s03A#", ln) and len(ln.split("#")[-1]) >= 8
                   and int(ln.split("#")[-1][2:4], 16) & 0x40])
    if p.returncode != 0:
        print("   ✗ rfa_sim.py exited %d\n%s" % (p.returncode, (err or "")[:400]))
        return False
    print("   rfa_sim.py OK; MS 0x3A execute-strobe frames seen: %d" % strobes)
    if strobes == 0:
        print("   ✗ NO strobe on the bus - the stimulus is not reaching the BCM.")
        print("     Baselining now would produce a meaningless 'all static'.")
        return False
    print("   ✓ stimulus confirmed on the wire\n")
    return True


def main():
    nib = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    probes = json.load(open(PLAN))["probes"]
    dids = [(int(p["did"], 16), p["watch"], p["why"]) for p in probes]

    print("waking...")
    wake()
    if not verify_stimulus(nib):
        raise SystemExit("stimulus not confirmed - refusing to record an "
                         "uncontrolled baseline")
    print("baselining %d DIDs on STOCK firmware, RKE nibble %d\n" % (len(dids), nib))

    result = {}
    for did, watch, why in dids:
        vals = []
        subprocess.run(["cansend", IFACE, "%s#023E80000000000000" % TESTER],
                       capture_output=True)
        v0 = read_did(did)
        press(nib)
        t0 = time.time()
        while time.time() - t0 < 3.0:
            v = read_did(did, to=0.35)
            if v is not None:
                vals.append(v)
            time.sleep(0.05)
        uniq = sorted(set(x for x in vals if x is not None))
        result["0x%04X" % did] = dict(watch=watch, why=why, idle=v0,
                                      observed=uniq, samples=len(vals))
        flag = "VARIES" if len(uniq) > 1 else "static"
        print("   0x%04X idle=%s  observed=%s  %s  (%s)"
              % (did, v0, ",".join(uniq) or "-", flag, watch))
        time.sleep(0.2)

    varying = [k for k, v in result.items() if len(v["observed"]) > 1]
    print("\n== summary ==")
    print("   DIDs whose OEM value VARIES under the stimulus: %d" % len(varying))
    print("   %s" % (", ".join(varying) or "none"))
    print("\n   Those are the ones to watch most carefully after the flash: a")
    print("   repointed probe must stop matching this OEM pattern.")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(dict(nibble=nib, baseline=result), open(OUT, "w"), indent=1)
    print("\nwrote %s" % OUT)


if __name__ == "__main__":
    main()
