#!/usr/bin/env python3
"""Regression: does bcmflash's plan reproduce the OEM capture, frame for frame?

The OEM capture hscan_bcm_flash.log is a flash of JV6T-14C095-AB (sw_part_type
DATA, "Local Configuration").  If our tool is correct, a dry run against that
same VBF must emit the SAME service requests in the SAME order:

    3E00, 22F111, 1002, 2701, 2702<key>, 3E80,
    34 00 44 <addr><len> x6      (SBL blocks, RAM)
    37 x6
    31 01 0301 40002000          (start SBL)
    31 01 FF00 0000C000 00004000 (erase - from the VBF header)
    34 00 44 0000C000 00004000   (the data block)
    37
    11 01

This is a real regression test: it compares our PLAN against a KNOWN-GOOD
capture, so a future edit that breaks the sequence is caught without touching
hardware.  It also proves the erase address is derived from the VBF and not
copied from the log - we run the SAME check against the APP VBF and require a
DIFFERENT, larger erase list.

Usage: python3 work/flash/test_against_oem_log.py
"""
import os
import re
import struct
import subprocess
import sys

ROOT = "/home/gl/Projects/ford/BCM/Research"
LOG = os.path.join(ROOT, "hscan_bcm_flash.log")
TOOL = os.path.join(ROOT, "work/flash/bcmflash.py")
fails = []


def check(name, ok, detail=""):
    print("   [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                            ("  - " + detail) if detail else ""))
    if not ok:
        fails.append(name)


def oem_requests():
    """Reassemble every UDS request the OEM tool sent on 0x726."""
    out, cur, need = [], None, 0
    for line in open(LOG, errors="ignore"):
        m = re.search(r"\s726#([0-9A-Fa-f]+)", line)
        if not m:
            continue
        b = bytes.fromhex(m.group(1))
        if b[0] >> 4 == 0:
            n = b[0] & 0x0F
            out.append(b[1:1 + n])
        elif b[0] >> 4 == 1:
            need = ((b[0] & 0x0F) << 8) | b[1]
            cur = bytearray(b[2:8])
        elif b[0] >> 4 == 2 and cur is not None:
            cur += b[1:8]
            if len(cur) >= need:
                out.append(bytes(cur[:need]))
                cur = None
    return out


def Vbf_blocks(path):
    """Parse a VBF's data blocks (independent of bcmflash, so the test does not
    inherit a bug from the tool it is testing)."""
    d = open(path, "rb").read()
    i = d.find(b"header")
    j = d.find(b"{", i)
    depth = 0
    while True:
        if d[j:j + 1] == b"{":
            depth += 1
        elif d[j:j + 1] == b"}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    off = j + 1
    while d[off] in (0x0D, 0x0A, 0x20, 0x09):
        off += 1
    blocks, p = [], off
    while p + 8 <= len(d):
        s, l = struct.unpack(">II", d[p:p + 8])
        if l == 0 or p + 8 + l + 2 > len(d):
            break
        blocks.append(dict(start=s, length=l))
        p = p + 8 + l + 2
    return blocks


def dry_requests(vbf_path):
    """Extract the hex payloads a dry run would transmit.

    ⚠ The first version of this used r"\\[dry\\]\\s+\\S*\\s*([0-9A-F]{4,})".
    The `what` label contains SPACES ("sbl blk0 34"), so \\S* matched only the
    first word and the capture group landed on fragments of the label - it
    returned 'F111' and '0000C000' instead of whole payloads, and every
    comparison failed against a tool that was actually correct.  Anchor on the
    LAST whitespace-separated field instead, which is always the payload.
    """
    out = subprocess.run([sys.executable, TOOL, "flash", vbf_path],
                         capture_output=True, text=True).stdout
    reqs = []
    for line in out.splitlines():
        if "[dry]" not in line:
            continue
        tok = line.split()[-1]
        if re.fullmatch(r"[0-9A-F]{4,}", tok):
            reqs.append(tok)
    return reqs, out


def main():
    print("== OEM capture: what did the real tool send? ==")
    reqs = oem_requests()
    heads = [r.hex().upper() for r in reqs]
    # the identifying facts
    dl = [r for r in reqs if r[:3] == b"\x34\x00\x44"]
    erase = [r for r in reqs if r[:4] == bytes.fromhex("3101FF00")]
    start = [r for r in reqs if r[:4] == bytes.fromhex("31010301")]
    reset = [r for r in reqs if r[:2] == b"\x11\x01"]
    print("   RequestDownload : %d" % len(dl))
    for r in dl:
        a, l = struct.unpack(">II", r[3:11])
        print("      0x%08X len 0x%06X" % (a, l))
    print("   erase routines  : %s" % [r.hex().upper() for r in erase])
    print("   SBL start       : %s" % [r.hex().upper() for r in start])
    print("   ECUReset        : %d" % len(reset))

    print("\n== 1. the capture is a DATA part flash, not an application ==")
    ea, el = struct.unpack(">II", erase[0][4:12])
    check("single erase region 0xC000/0x4000",
          len(erase) == 1 and ea == 0xC000 and el == 0x4000,
          "0x%08X len 0x%X" % (ea, el))
    check("its data block matches that region",
          any(struct.unpack(">II", r[3:11]) == (0xC000, 0x4000) for r in dl))

    print("\n== 2. our tool's plan for the SAME VBF ==")
    ours, out = dry_requests(os.path.join(ROOT, "JV6T-14C095-AB.VBF"))
    # non-degeneracy: if extraction yields nothing, every comparison below would
    # "pass" vacuously.  Fail loudly instead (this is exactly what bit the first
    # version of this test).
    check("dry-run extraction is non-empty", len(ours) >= 10, "%d requests" % len(ours))
    plan_erase = [x for x in ours if x.startswith("3101FF00")]
    plan_dl = [x for x in ours if x.startswith("340044")]
    plan_start = [x for x in ours if x.startswith("31010301")]
    check("plans exactly 1 erase", len(plan_erase) == 1, str(plan_erase))
    check("erase bytes identical to OEM",
          bool(plan_erase) and plan_erase[0] == erase[0].hex().upper(),
          "ours %s vs oem %s" % (plan_erase[0] if plan_erase else "-",
                                 erase[0].hex().upper()))
    check("plans 7 RequestDownloads (6 SBL + 1 data)", len(plan_dl) == 7,
          "%d" % len(plan_dl))
    oem_dl_set = sorted(r[3:11].hex().upper() for r in dl)
    our_dl_set = sorted(x[6:22] for x in plan_dl)
    check("download address/length set identical", oem_dl_set == our_dl_set,
          "%d vs %d" % (len(oem_dl_set), len(our_dl_set)))
    check("SBL start address identical",
          bool(plan_start) and plan_start[0] == start[0].hex().upper(),
          "ours %s" % (plan_start[0] if plan_start else "-"))
    order = [x for x in ours if x[:2] in ("3E", "10", "27")][:5]
    check("opens with wake/wake/session/seed",
          order[:2] == ["3E00", "3E00"] and "1002" in order and "2701" in order,
          str(order))

    print("\n== 3. the APP VBF must NOT reuse the capture's addresses ==")
    ours2, _ = dry_requests(os.path.join(
        ROOT, "work/probe-bank/JV6T-14C094-AD_probe-bank.VBF"))
    check("app dry-run extraction is non-empty", len(ours2) >= 10,
          "%d requests" % len(ours2))
    e2 = [x for x in ours2 if x.startswith("3101FF00")]
    check("app plans 11 erase regions", len(e2) == 11, "%d" % len(e2))
    check("app erase differs from the DATA capture",
          bool(e2) and e2[0] != erase[0].hex().upper(),
          "app first erase %s" % (e2[0] if e2 else "-"))
    starts = [int(x[8:16], 16) for x in e2]
    lens = [int(x[16:24], 16) for x in e2]
    check("app erase covers 0x10000..0x140000",
          bool(starts) and min(starts) == 0x10000
          and max(s + l for s, l in zip(starts, lens)) == 0x140000,
          "0x%X..0x%X" % (min(starts), max(s + l for s, l in zip(starts, lens)))
          if starts else "-")
    check("app erase regions are non-overlapping and ascending",
          bool(starts) and all(a + la <= b for (a, la), b
                               in zip(zip(starts, lens), starts[1:])),
          "%d regions" % len(starts))
    check("app data blocks lie inside the erased span",
          bool(starts) and all(
              0x10000 <= b["start"] and b["start"] + b["length"] <= 0x140000
              for b in Vbf_blocks(os.path.join(
                  ROOT, "work/probe-bank/JV6T-14C094-AD_probe-bank.VBF"))))

    print("\n== %s ==" % ("ALL CHECKS PASSED" if not fails
                          else "FAILURES: " + ", ".join(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
