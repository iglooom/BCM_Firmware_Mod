#!/usr/bin/env python3
"""Summarise a command-enum sweep: nibble -> 0x3A d3 + execute strobes.

Reads the sweep JSON written by rfa_sim.py and prints the enum table, which is
the direct on-wire test of the static claim that the RKE command is consumed as
an ENUM ((code & 0xF) == 1 is LOCK) rather than as a 0x01/0x02 bitmask
(AGENTS.md rule 13).

A bitmask model predicts: bit0 set -> LOCK for nibbles 1,3,5,7,9,B,D,F.
An enum model predicts:   ONLY nibble 1 -> LOCK, only nibble 2 -> UNLOCK.
These differ on 6+ of the 16 cells, so the sweep discriminates cleanly.
"""
import glob
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else sorted(
    glob.glob("logs/*sweep_nibble.json"))[-1]
d = json.load(open(path))
per = d["per_nibble"]

print("sweep: %s\n" % path)
print("nib | lock frames | d3 values seen        | strobes | verdict")
print("----+-------------+-----------------------+---------+---------------")
enum_hits = {}
for n in range(16):
    e = per.get(str(n))
    if not e:
        continue
    d3 = e["d3_values"]
    # the command actually asserted in this slice (ignore 0x0 = idle)
    active = {k: v for k, v in d3.items() if k != "0x0"}
    verdict = ""
    if "0x1" in active:
        verdict = "LOCK"
    if "0x2" in active:
        verdict = (verdict + "+UNLOCK") if verdict else "UNLOCK"
    if not verdict:
        verdict = "-"
    enum_hits[n] = verdict
    print("%3d | %11d | %-21s | %7d | %s"
          % (n, e["lock_frames"], ",".join(sorted(active)) or "-",
             e["strobe_count"], verdict))

print("\n--- model discrimination ---")
bitmask_lock = {n for n in range(16) if n & 1}
bitmask_unlock = {n for n in range(16) if n & 2}
enum_lock = {n for n, v in enum_hits.items() if v.startswith("LOCK")}
enum_unlock = {n for n, v in enum_hits.items() if "UNLOCK" in v}
print("observed LOCK   nibbles: %s" % sorted(enum_lock))
print("observed UNLOCK nibbles: %s" % sorted(enum_unlock))
print("bitmask model would predict LOCK on   %s" % sorted(bitmask_lock))
print("bitmask model would predict UNLOCK on %s" % sorted(bitmask_unlock))
if enum_lock == {1} and enum_unlock == {2}:
    print("\n=> ENUM model CONFIRMED: exactly one nibble each. Rule 13 holds on the wire.")
elif enum_lock == bitmask_lock:
    print("\n=> BITMASK model matches - the static enum reading would need revisiting.")
else:
    print("\n=> Neither clean model. Report the table as-is; do not force a model.")
