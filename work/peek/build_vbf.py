#!/usr/bin/env python3
"""Build the PEEK app VBF: one hook + one cave giving arbitrary memory read
over UDS 0x22.

Wire format (bench-measured, work/bench/peek_carrier_raw.py):
    22 DE AD <A3> <A2> <A1> <A0>  ->  62 DE AD <4 bytes at 0xA3A2A1A0>

Edits (from work/peek/peek_blobs.json, all Ghidra-assembled and round-tripped):
    0x0010B764  4 bytes    e_cmpli cr0,r26,0xee00  ->  e_b 0x00118000
    0x00118000  438 bytes  0xFF padding            ->  the cave

Then all THREE integrity layers are repaired in order (AGENTS.md 2.1 / 5):
    1. internal sum8  @ 0x13FFFE
    2. per-block CRC-16 (CCITT-FALSE)
    3. file CRC-32 in the 'file_checksum' header field

Guards: the hook site asserts its EXPECTED OEM bytes, and the whole cave span
is asserted to be 0xFF padding, so a wrong address or version drift aborts
instead of corrupting the image.  It also asserts the cave does not overlap the
acc-fix / rke-lock caves at 0x117100 / 0x117300.
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
OUTD = os.path.join(ROOT, "work", "peek")
BK = os.path.join(ROOT, "work", "backups")
BLOBS = os.path.join(OUTD, "peek_blobs.json")
APP_BASE = 0x10020
SUM8_AT = 0x13FFFE
ACCFIX_CAVES = (0x117100, 0x117300)


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

    blobs = json.load(open(BLOBS))
    cave_addr = blobs["cave_addr"]
    cave = bytes(blobs["cave"])
    hook_addr = blobs["hook_addr"]
    hook = bytes(blobs["hook"])
    oem_hook = bytes(blobs["oem_hook_bytes"])

    # --- static sanity on the plan itself --------------------------------
    for c in ACCFIX_CAVES:
        assert not (cave_addr <= c < cave_addr + len(cave)), \
            "cave overlaps the acc-fix cave at 0x%X" % c
    assert len(hook) == len(oem_hook) == 4, "hook must be a 4-byte branch"

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

    # ---- guard + apply: the hook ----------------------------------------
    o = fo(hook_addr)
    got = bytes(d[o:o + 4])
    assert got == oem_hook, ("HOOK GUARD FAILED at 0x%06X\n  expected %s\n"
                             "  found    %s" % (hook_addr, oem_hook.hex(),
                                                got.hex()))
    print("hook  @0x%06X  %s -> %s  (guard OK)"
          % (hook_addr, got.hex().upper(), hook.hex().upper()))
    d[o:o + 4] = hook

    # ---- guard + apply: the cave ----------------------------------------
    o = fo(cave_addr)
    span = bytes(d[o:o + len(cave)])
    assert span == b"\xFF" * len(cave), (
        "CAVE GUARD FAILED: 0x%06X..0x%06X is not all-0xFF padding "
        "(%d non-FF bytes)" % (cave_addr, cave_addr + len(cave),
                               sum(1 for b in span if b != 0xFF)))
    print("cave  @0x%06X  %d bytes of 0xFF padding  (guard OK)"
          % (cave_addr, len(cave)))
    d[o:o + len(cave)] = cave

    # ---- layer 1: internal sum8 -----------------------------------------
    flat = bytearray(b"\xFF" * (0x140000 - 0x10000))
    flat[0:rchw["length"]] = d[rchw["dataoff"]:rchw["dataoff"] + rchw["length"]]
    flat[0x20:0x20 + appblk["length"]] = \
        d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]]
    o = fo(SUM8_AT)
    old = struct.unpack_from(">H", d, o)[0]
    new = sum(flat[0:SUM8_AT - 0x10000]) & 0xFFFF
    struct.pack_into(">H", d, o, new)
    print("\n   sum8   0x%04X -> 0x%04X" % (old, new))

    # ---- layer 2: per-block CRC-16 --------------------------------------
    for b in blocks:
        c = crc16(bytes(d[b["dataoff"]:b["dataoff"] + b["length"]]))
        d[b["crcoff"]:b["crcoff"] + 2] = struct.pack(">H", c)
        print("   crc16  block 0x%X -> 0x%04X" % (b["start"], c))

    # ---- layer 3: file CRC-32 -------------------------------------------
    m = re.search(rb"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", bytes(d[:ds]))
    fc = zlib.crc32(bytes(d[ds:])) & 0xFFFFFFFF
    w = len(m.group(1))
    d[m.start(1):m.end(1)] = ("%0*X" % (w, fc)).encode()
    print("   crc32  file -> 0x%08X" % fc)

    outp = os.path.join(OUTD, "JV6T-14C094-AD_peek.VBF")
    open(outp, "wb").write(d)
    h = hashlib.sha256(bytes(d)).hexdigest()
    print("\nWROTE %s\n   sha256 %s" % (outp, h))
    json.dump(dict(vbf=outp, sha256=h, cave_addr=cave_addr,
                   cave_len=len(cave), hook_addr=hook_addr,
                   magic=blobs["magic"], scratch=blobs["scratch"],
                   sum8=new, crc32=fc),
              open(os.path.join(OUTD, "build_info.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
