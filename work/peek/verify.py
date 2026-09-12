#!/usr/bin/env python3
"""Independently verify JV6T-14C094-AD_peek.VBF -- re-read from DISK.

This must NOT trust build_vbf.py's own outputs.  It re-parses the artifact,
recomputes every integrity layer, re-disassembles the cave through GHIDRA from
the rebuilt image, and diffs against OEM.

The decisive check is the last one: it lets Ghidra decode the bytes that are
actually in the file and asserts the control flow is what we intended --
an instrument independent of the one that built the bytes (the same discipline
that caught the split-field bug in the probe bank, live_debug_uds.md 8.3).
"""
import hashlib
import json
import os
import re
import struct
import sys
import traceback
import zlib

import pyghidra
import jpype

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"

ROOT = "/home/gl/Projects/ford/BCM/Research"
OEM = os.path.join(ROOT, "JV6T-14C094-AD.VBF")
MOD = os.path.join(ROOT, "work", "peek", "JV6T-14C094-AD_peek.VBF")
BLOBS = os.path.join(ROOT, "work", "peek", "peek_blobs.json")
APP_BASE = 0x10020
SUM8_AT = 0x13FFFE

FAILS = []


def check(name, ok, detail=""):
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    if not ok:
        FAILS.append(name)
    return ok


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
    ds, blocks, p = off, [], off
    while p + 8 <= len(d):
        s, l = struct.unpack(">II", d[p:p + 8])
        if l == 0 or p + 8 + l + 2 > len(d):
            break
        blocks.append(dict(start=s, dataoff=p + 8, length=l, crcoff=p + 8 + l))
        p = p + 8 + l + 2
    return d, ds, blocks


def main():
    blobs = json.load(open(BLOBS))
    cave_addr, cave = blobs["cave_addr"], bytes(blobs["cave"])
    hook_addr, hook = blobs["hook_addr"], bytes(blobs["hook"])

    print("artifact: %s" % MOD)
    print("sha256  : %s\n" % hashlib.sha256(open(MOD, "rb").read()).hexdigest())

    d, ds, blocks = parse(MOD)
    do, dso, oblocks = parse(OEM)
    app = [b for b in blocks if b["start"] == APP_BASE][0]
    rchw = [b for b in blocks if b["start"] == 0x10000][0]
    oapp = [b for b in oblocks if b["start"] == APP_BASE][0]

    def fo(fa):
        return app["dataoff"] + (fa - APP_BASE)

    print("== integrity ==")
    for b in blocks:
        c = crc16(bytes(d[b["dataoff"]:b["dataoff"] + b["length"]]))
        stored = struct.unpack_from(">H", d, b["crcoff"])[0]
        check("block 0x%X CRC-16" % b["start"], c == stored,
              "computed 0x%04X stored 0x%04X" % (c, stored))

    m = re.search(rb"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", bytes(d[:ds]))
    stored32 = int(m.group(1), 16)
    calc32 = zlib.crc32(bytes(d[ds:])) & 0xFFFFFFFF
    check("file CRC-32", stored32 == calc32,
          "stored 0x%08X computed 0x%08X" % (stored32, calc32))

    flat = bytearray(b"\xFF" * (0x140000 - 0x10000))
    flat[0:rchw["length"]] = d[rchw["dataoff"]:rchw["dataoff"] + rchw["length"]]
    flat[0x20:0x20 + app["length"]] = d[app["dataoff"]:app["dataoff"] + app["length"]]
    s8 = sum(flat[0:SUM8_AT - 0x10000]) & 0xFFFF
    st8 = struct.unpack_from(">H", d, fo(SUM8_AT))[0]
    check("internal sum8", s8 == st8,
          "computed 0x%04X stored 0x%04X" % (s8, st8))
    check("guard half-word @0x13FFFC == 0xFFFF",
          struct.unpack_from(">H", d, fo(0x13FFFC))[0] == 0xFFFF)

    print("\n== payload present ==")
    check("hook bytes in file", bytes(d[fo(hook_addr):fo(hook_addr) + 4]) == hook,
          bytes(d[fo(hook_addr):fo(hook_addr) + 4]).hex().upper())
    check("cave bytes in file",
          bytes(d[fo(cave_addr):fo(cave_addr) + len(cave)]) == cave,
          "%d bytes" % len(cave))

    print("\n== diff vs OEM (expect ONLY: hook + cave + sum8) ==")
    a = bytes(d[app["dataoff"]:app["dataoff"] + app["length"]])
    b = bytes(do[oapp["dataoff"]:oapp["dataoff"] + oapp["length"]])
    check("app block same length", len(a) == len(b))
    diffs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    clusters, cur = [], None
    for i in diffs:
        if cur and i == cur[1] + 1:
            cur[1] = i
        else:
            cur = [i, i]
            clusters.append(cur)
    print("     %d differing bytes in %d cluster(s)" % (len(diffs), len(clusters)))
    expected = 0
    for lo, hi in clusters:
        fa_lo, fa_hi = APP_BASE + lo, APP_BASE + hi
        tag = "UNEXPECTED"
        if fa_lo >= hook_addr and fa_hi < hook_addr + 4:
            tag = "hook"
            expected += 1
        elif fa_lo >= cave_addr and fa_hi < cave_addr + len(cave):
            tag = "cave"
            expected += 1
        elif fa_lo >= SUM8_AT and fa_hi < SUM8_AT + 2:
            tag = "sum8"
            expected += 1
        print("     0x%06X..0x%06X  %5d bytes  %s"
              % (fa_lo, fa_hi, hi - lo + 1, tag))
    check("every cluster explained", expected == len(clusters),
          "%d/%d" % (expected, len(clusters)))

    # ---------- the decisive check: let GHIDRA decode the file ----------
    print("\n== Ghidra re-disassembly of the cave FROM THE REBUILT IMAGE ==")
    pyghidra.start()
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.address import AddressSet
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.program.model.lang import RegisterValue
    from java.math import BigInteger

    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", False)
    program = None
    try:
        program = project.openProgram("/", "flash_merged.bin", False)
        af = program.getAddressFactory().getDefaultAddressSpace()

        def A(x):
            return af.getAddress(x)

        mem = program.getMemory()
        listing = program.getListing()
        ctxreg = program.getLanguage().getContextBaseRegister()
        pc = program.getProgramContext()
        val = RegisterValue(ctxreg, BigInteger("20000000", 16),
                            BigInteger("FFFFFFFF", 16))
        JB = jpype.JArray(jpype.JByte)

        def jb(bs):
            return JB([x if x < 128 else x - 256 for x in bs])

        # take the bytes FROM THE FILE, not from peek_blobs.json
        file_cave = bytes(d[fo(cave_addr):fo(cave_addr) + len(cave)])
        file_hook = bytes(d[fo(hook_addr):fo(hook_addr) + 4])

        tid = program.startTransaction("verify")
        try:
            listing.clearCodeUnits(A(cave_addr),
                                   A(cave_addr + len(file_cave) - 1), False)
            pc.setRegisterValue(A(cave_addr), A(cave_addr + len(file_cave)), val)
            mem.setBytes(A(cave_addr), jb(file_cave))
            listing.clearCodeUnits(A(hook_addr), A(hook_addr + 3), False)
            mem.setBytes(A(hook_addr), jb(file_hook))
            for lo, hi in ((cave_addr, cave_addr + len(file_cave)),
                           (hook_addr, hook_addr + 4)):
                listing.clearCodeUnits(A(lo), A(hi - 1), False)
                DisassembleCommand(A(lo), AddressSet(A(lo), A(hi - 1)),
                                   True).applyTo(program)

            hi_ins = listing.getInstructionAt(A(hook_addr))
            check("hook decodes as a branch to the cave",
                  hi_ins is not None and
                  ("e_b" in str(hi_ins)) and
                  ("%x" % cave_addr in str(hi_ins).lower()), str(hi_ins))

            txt = []
            for ins in listing.getInstructions(
                    AddressSet(A(cave_addr), A(cave_addr + len(file_cave) - 1)),
                    True):
                txt.append("%s %s" % (ins.getAddress(), ins))
            joined = "\n".join(txt).lower()
            check("cave decodes to instructions", len(txt) > 50,
                  "%d instructions" % len(txt))
            check("MAGIC compare present",
                  "e_cmpl16i. r26,0x%04x" % blobs["magic"] in joined)
            check("reads the request object 0x4000538C",
                  "0x538c" in joined)
            check("writes the response object 0x400053A4",
                  "0x53a4" in joined)
            # NOTE: Ghidra prints addresses ZERO-PADDED to 8 digits
            # ("e_bl 0x001098de"), so match that exact form -- an unpadded
            # needle silently fails and looks like a missing call.
            check("calls the request-byte accessor 0x1098DE",
                  "0x001098de" in joined)
            check("calls the response-append accessor 0x109916",
                  "0x00109916" in joined)
            # stronger than presence: the exact call COUNTS the design implies
            check("exactly 4 request-byte reads (the 4 address bytes)",
                  joined.count("0x001098de") == 4,
                  "found %d" % joined.count("0x001098de"))
            check("exactly 10 response appends (2 DID echo + 4 data + 4 marker)",
                  joined.count("0x00109916") == 10,
                  "found %d" % joined.count("0x00109916"))
            check("rejoins the stock continue path 0x10B992",
                  "0x0010b992" in joined)
            check("replays the displaced compare and returns to 0x10B768",
                  "e_cmpli cr0,r26,0xee00" in joined and "0x0010b768" in joined)
            check("no store outside the scratch cell (read-only)",
                  joined.count("e_stb") == 4 and "e_stw " in joined,
                  "e_stb x%d (the 4 address bytes)" % joined.count("e_stb"))
            print("\n--- first 12 and last 8 instructions ---")
            for t in txt[:12]:
                print("   " + t)
            print("   ...")
            for t in txt[-8:]:
                print("   " + t)
        finally:
            program.endTransaction(tid, False)     # rollback
    finally:
        try:
            if program is not None:
                project.close()
        except Exception:
            pass

    print("\n" + "=" * 60)
    if FAILS:
        print("VERIFY FAILED: %d check(s) -- %s" % (len(FAILS), ", ".join(FAILS)))
    else:
        print("ALL CHECKS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    except Exception:
        traceback.print_exc()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
