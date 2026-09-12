#!/usr/bin/env python3
"""Build the PROBE-BANK app VBF: 17 DID readers repointed at chosen RAM cells.

Each probe is a 4-byte edit to one OEM DID reader's two address immediates:

    e_lis  r7,HIGH        <- assembled by Ghidra (rule 3; the immediate is a
    e_lbz  r7,LOW(r7)        SPLIT FIELD and must never be hand-built)
    se_stb r7,0x0(r3)     <- OEM tail kept verbatim
    se_mr  r3,r4
    se_blr

After the edits, all THREE integrity layers are repaired in order (AGENTS.md
2.1 / 5), or the BCM boots into a software-integrity fault:
    1. internal sum8  @ 0x13FFFE
    2. per-block CRC-16 (CCITT-FALSE)
    3. file CRC-32 in the 'file_checksum' header field

Guards: every edit site asserts its EXPECTED OEM bytes first, so a wrong address
or a version mismatch aborts instead of corrupting the image.

Input : work/owner/probe_bank_bytes.json  (from 272, Ghidra-assembled)
Output: work/probe-bank/JV6T-14C094-AD_probe-bank.VBF
"""
import hashlib
import json
import os
import re
import shutil
import struct
import zlib

ROOT = "/home/gl/Projects/ford/BCM/Research"
SRC = os.path.join(ROOT, "JV6T-14C094-AD.VBF")
OUTD = os.path.join(ROOT, "work", "probe-bank")
BK = os.path.join(ROOT, "work", "backups")
PLAN = os.path.join(ROOT, "work/owner/probe_bank_bytes.json")
APP_BASE = 0x10020
SUM8_AT = 0x13FFFE


def crc16(d):
    c = 0xFFFF
    for b in d:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
    return c


def hdr_end(d):
    i = d.find(b"header")
    depth = 0
    j = d.find(b"{", i)
    while j < len(d):
        if d[j] == 0x7B:
            depth += 1
        elif d[j] == 0x7D:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1


def parse(path):
    d = bytearray(open(path, "rb").read())
    off = hdr_end(d)
    while d[off] in (0x0D, 0x0A, 0x20, 0x09):
        off += 1
    ds = off
    blocks = []
    p = off
    while p + 8 <= len(d):
        s, l = struct.unpack(">II", d[p:p + 8])
        if l == 0 or p + 8 + l + 2 > len(d):
            break
        blocks.append(dict(start=s, dataoff=p + 8, length=l, crcoff=p + 8 + l))
        p = p + 8 + l + 2
    return d, ds, blocks


def main():
    os.makedirs(OUTD, exist_ok=True)
    os.makedirs(BK, exist_ok=True)

    h_src = hashlib.sha256(open(SRC, "rb").read()).hexdigest()
    print("source VBF sha256 %s" % h_src)
    assert h_src.startswith("1569cde589ec546f"), "unexpected source VBF"
    bpath = os.path.join(BK, os.path.basename(SRC) + ".orig_%s" % h_src[:12])
    if not os.path.exists(bpath):
        shutil.copy2(SRC, bpath)

    d, ds, blocks = parse(SRC)
    appblk = [b for b in blocks if b["start"] == APP_BASE][0]
    rchw = [b for b in blocks if b["start"] == 0x10000][0]
    print("app block 0x%X len 0x%X\n" % (appblk["start"], appblk["length"]))

    def fo(fa):
        assert APP_BASE <= fa < APP_BASE + appblk["length"], \
            "0x%X outside the app block" % fa
        return appblk["dataoff"] + (fa - APP_BASE)

    probes = json.load(open(PLAN))["probes"]
    print("== applying %d probe edits (expected-byte guarded) ==" % len(probes))
    for p in probes:
        fa = int(p["reader"], 16)
        exp = bytes.fromhex(p["old_bytes"].replace(" ", ""))
        new = bytes.fromhex(p["new_bytes"].replace(" ", ""))
        assert len(exp) == len(new) == 14, "probe must be 14 bytes"
        o = fo(fa)
        got = bytes(d[o:o + len(exp)])
        assert got == exp, ("GUARD FAILED at 0x%06X\n   expected %s\n   found    %s"
                            % (fa, exp.hex(), got.hex()))
        # only the two immediates may differ; the tail must be untouched
        assert exp[8:] == new[8:], "probe changed the OEM tail"
        d[o:o + len(new)] = new
        print("   %s @ 0x%06X -> %s" % (p["did"], fa, p["watch"]))

    # ---- layer 1: internal sum8 -------------------------------------------
    flat = bytearray(b"\xFF" * (0x140000 - 0x10000))
    flat[0:rchw["length"]] = d[rchw["dataoff"]:rchw["dataoff"] + rchw["length"]]
    flat[0x20:0x20 + appblk["length"]] = \
        d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]]
    o = fo(SUM8_AT)
    old = struct.unpack_from(">H", d, o)[0]
    new = sum(flat[0:SUM8_AT - 0x10000]) & 0xFFFF
    struct.pack_into(">H", d, o, new)
    print("\n   sum8   0x%04X -> 0x%04X" % (old, new))

    # ---- layer 2: per-block CRC-16 ----------------------------------------
    for b in blocks:
        c = crc16(bytes(d[b["dataoff"]:b["dataoff"] + b["length"]]))
        d[b["crcoff"]:b["crcoff"] + 2] = struct.pack(">H", c)
        print("   crc16  block 0x%X -> 0x%04X" % (b["start"], c))

    # ---- layer 3: file CRC-32 --------------------------------------------
    m = re.search(rb"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", bytes(d[:ds]))
    fc = zlib.crc32(bytes(d[ds:])) & 0xFFFFFFFF
    w = len(m.group(1))
    d[m.start(1):m.end(1)] = ("%0*X" % (w, fc)).encode()
    print("   crc32  file -> 0x%08X" % fc)

    outp = os.path.join(OUTD, "JV6T-14C094-AD_probe-bank.VBF")
    open(outp, "wb").write(d)
    h = hashlib.sha256(bytes(d)).hexdigest()
    print("\nWROTE %s\n   sha256 %s" % (outp, h))
    json.dump(dict(vbf=outp, sha256=h, probes=len(probes),
                   sum8=new, crc32=fc),
              open(os.path.join(OUTD, "build_info.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
