#!/usr/bin/env python3
"""Build the COMBINED peek + remote-start-trigger app VBF.

Four edits, all Ghidra-assembled and round-trip verified:
    1. 0x0010B764   4 B   e_cmpli cr0,r26,0xee00 -> e_b 0x00118000   (peek hook)
    2. 0x00118000 438 B   0xFF padding           -> peek cave
    3. 0x001181B2   4 B   e_b 0x0010B768         -> e_b 0x00119000   (chain)
    4. 0x00119000 298 B   0xFF padding           -> rs-trigger cave

Edit 3 is what makes this a CHAIN rather than a second hook: peek's "not my
DID" tail, which used to return to stock, now falls into the rs cave, whose
own "not my DID" tail replays the displaced e_cmpli and returns to stock.
One hook, one displaced instruction (AGENTS.md Sec.7).

Then all THREE integrity layers, in order (rule 2):
    1. internal sum8 @0x13FFFE   2. per-block CRC-16   3. file CRC-32

GUARDS -- every edit asserts its expected pre-edit bytes, so a wrong address or
version drift ABORTS instead of corrupting the image:
  * hook site must hold the OEM e_cmpli bytes;
  * peek cave span must be all-0xFF *or* already hold the exact peek bytes
    (this script is idempotent w.r.t. a previous peek build);
  * the chain site must hold peek's ORIGINAL tail branch;
  * rs cave span must be all-0xFF;
  * neither cave may overlap acc-fix 0x117100 / 0x117300 or each other.

⚠ SAFETY: this build can START AN ENGINE from a CAN message.
   See docs/rs_trigger_design.md Sec.1 before flashing anything.
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
OUTD = os.path.join(ROOT, "work", "rs-trigger")
BK = os.path.join(ROOT, "work", "backups")
PEEK_BLOBS = os.path.join(ROOT, "work", "peek", "peek_blobs.json")
RS_BLOBS = os.path.join(OUTD, "rs_blobs.json")
APP_BASE = 0x10020
SUM8_AT = 0x13FFFE
ACCFIX_CAVES = (0x117100, 0x117300)
SRC_SHA_PREFIX = "1569cde589ec546f"


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
        s, ln = struct.unpack(">II", d[p:p + 8])
        if ln == 0 or p + 8 + ln + 2 > len(d):
            break
        blocks.append(dict(start=s, dataoff=p + 8, length=ln, crcoff=p + 8 + ln))
        p = p + 8 + ln + 2
    return d, ds, blocks


def main():
    os.makedirs(OUTD, exist_ok=True)
    os.makedirs(BK, exist_ok=True)

    pk = json.load(open(PEEK_BLOBS))
    rs = json.load(open(RS_BLOBS))

    peek_cave_addr = pk["cave_addr"]
    peek_cave = bytes(pk["cave"])
    hook_addr = pk["hook_addr"]
    hook = bytes(pk["hook"])
    oem_hook = bytes(pk["oem_hook_bytes"])

    rs_cave_addr = rs["cave_addr"]
    rs_cave = bytes(rs["cave"])
    tail_addr = rs["peek_tail_addr"]
    tail_old = bytes(rs["peek_tail_old"])
    tail_new = bytes(rs["peek_tail_new"])

    # --- static sanity on the plan ---------------------------------------
    assert len(hook) == len(oem_hook) == 4, "hook must be a 4-byte branch"
    assert len(tail_old) == len(tail_new) == 4, "chain branch must be 4 bytes"
    for c in ACCFIX_CAVES:
        for base, ln, nm in ((peek_cave_addr, len(peek_cave), "peek"),
                             (rs_cave_addr, len(rs_cave), "rs")):
            assert not (base <= c < base + ln), \
                "%s cave overlaps acc-fix cave 0x%X" % (nm, c)
    assert (rs_cave_addr >= peek_cave_addr + len(peek_cave)
            or peek_cave_addr >= rs_cave_addr + len(rs_cave)), \
        "peek and rs caves overlap"
    assert peek_cave_addr <= tail_addr < peek_cave_addr + len(peek_cave), \
        "chain site is not inside the peek cave"

    h_src = hashlib.sha256(open(SRC, "rb").read()).hexdigest()
    print("source VBF sha256 %s" % h_src)
    assert h_src.startswith(SRC_SHA_PREFIX), "unexpected source VBF"
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

    # ---- edit 1: the hook ------------------------------------------------
    o = fo(hook_addr)
    got = bytes(d[o:o + 4])
    assert got == oem_hook, ("HOOK GUARD FAILED at 0x%06X\n  expected %s\n"
                             "  found    %s"
                             % (hook_addr, oem_hook.hex(), got.hex()))
    print("1 hook  @0x%06X  %s -> %s  (guard OK)"
          % (hook_addr, got.hex().upper(), hook.hex().upper()))
    d[o:o + 4] = hook

    # ---- edit 2: the peek cave ------------------------------------------
    o = fo(peek_cave_addr)
    span = bytes(d[o:o + len(peek_cave)])
    assert span == b"\xFF" * len(peek_cave), (
        "PEEK CAVE GUARD FAILED: 0x%06X is not all-0xFF (%d non-FF)"
        % (peek_cave_addr, sum(1 for b in span if b != 0xFF)))
    print("2 peek  @0x%06X  %d bytes of 0xFF padding  (guard OK)"
          % (peek_cave_addr, len(peek_cave)))
    d[o:o + len(peek_cave)] = peek_cave

    # ---- edit 3: retarget peek's tail into the rs cave -------------------
    o = fo(tail_addr)
    got = bytes(d[o:o + 4])
    assert got == tail_old, (
        "CHAIN GUARD FAILED at 0x%06X\n  expected %s (peek's tail branch)\n"
        "  found    %s" % (tail_addr, tail_old.hex(), got.hex()))
    print("3 chain @0x%06X  %s -> %s  (guard OK)"
          % (tail_addr, got.hex().upper(), tail_new.hex().upper()))
    d[o:o + 4] = tail_new

    # ---- edit 4: the rs cave --------------------------------------------
    o = fo(rs_cave_addr)
    span = bytes(d[o:o + len(rs_cave)])
    assert span == b"\xFF" * len(rs_cave), (
        "RS CAVE GUARD FAILED: 0x%06X is not all-0xFF (%d non-FF)"
        % (rs_cave_addr, sum(1 for b in span if b != 0xFF)))
    print("4 rs    @0x%06X  %d bytes of 0xFF padding  (guard OK)"
          % (rs_cave_addr, len(rs_cave)))
    d[o:o + len(rs_cave)] = rs_cave

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

    outp = os.path.join(OUTD, "JV6T-14C094-AD_peek-rstrigger.VBF")
    open(outp, "wb").write(d)
    h = hashlib.sha256(bytes(d)).hexdigest()
    print("\nWROTE %s\n   sha256 %s" % (outp, h))
    json.dump(dict(vbf=outp, sha256=h,
                   peek_cave=peek_cave_addr, peek_len=len(peek_cave),
                   rs_cave=rs_cave_addr, rs_len=len(rs_cave),
                   chain_at=tail_addr, hook_addr=hook_addr,
                   depths=rs["depths"], targets=rs["targets"],
                   sum8=new, crc32=fc),
              open(os.path.join(OUTD, "build_info.json"), "w"), indent=1)
    print("\n⚠ This build can start an engine from a CAN message.")
    print("  Read docs/rs_trigger_design.md Sec.1 before flashing.")


if __name__ == "__main__":
    main()
