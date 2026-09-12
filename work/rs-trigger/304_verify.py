#!/usr/bin/env python3
"""Verify the combined peek + rs-trigger VBF INDEPENDENTLY, from the artifact
on disk -- not from the builder's in-memory state.

AGENTS.md Sec.8 "definition of done":
  * every block CRC-16 OK, file CRC-32 OK, internal sum8 OK
  * both caves re-disassemble from the REBUILT image exactly as intended
  * the hook and the chain branch point where they should
  * diff vs OEM shows ONLY the expected clusters

Extra checks specific to this mod, each of which would be a real defect:
  V1  every store in the rs cave targets one of the DECLARED target cells --
      no store to an undeclared address (a wrong e_lis/e_add16i pair would
      show up here even though the cave "looks" right)
  V2  no store precedes the first MAGIC compare (nothing fires on a stock DID)
  V3  the three MAGIC constants in the image are exactly the three probed FREE
      on hardware by 302_stock_did_probe.py
  V4  the chain is closed: peek tail -> rs cave, rs tail -> stock RET

V1 is the one that matters most: it is the difference between "the listing
looks plausible" and "every write goes where the design says".
"""
import json
import os
import re
import struct
import sys
import traceback
import zlib

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
import pyghidra  # noqa: E402

pyghidra.start()
from ghidra.base.project import GhidraProject  # noqa: E402
from ghidra.program.model.address import AddressSet  # noqa: E402
from ghidra.app.cmd.disassemble import DisassembleCommand  # noqa: E402
from ghidra.program.model.lang import RegisterValue  # noqa: E402
from java.math import BigInteger  # noqa: E402
import jpype  # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
OUTD = os.path.join(ROOT, "work", "rs-trigger")
VBF = os.path.join(OUTD, "JV6T-14C094-AD_peek-rstrigger.VBF")
OEM = os.path.join(ROOT, "JV6T-14C094-AD.VBF")
APP_BASE = 0x10020
SUM8_AT = 0x13FFFE
FREE_MAGICS = [0xDE13, 0xDE16, 0xDE2C, 0xDE38, 0xDE4A]   # proven free on bench #1


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
    blocks, p = [], off
    while p + 8 <= len(d):
        s, ln = struct.unpack(">II", d[p:p + 8])
        if ln == 0 or p + 8 + ln + 2 > len(d):
            break
        blocks.append(dict(start=s, dataoff=p + 8, length=ln, crcoff=p + 8 + ln))
        p = p + 8 + ln + 2
    return d, ds, blocks


def main():
    fails = []

    def check(name, ok, detail=""):
        print("  %-52s %s%s" % (name, "PASS" if ok else "FAIL",
                                ("  " + detail) if detail else ""))
        if not ok:
            fails.append(name)

    info = json.load(open(os.path.join(OUTD, "build_info.json")))
    rs = json.load(open(os.path.join(OUTD, "rs_blobs.json")))
    # ⚠ Build the declared-target set from EVERY key the builder emitted, not a
    # hand-maintained list.  The first version enumerated five names, so adding
    # depth 4 made V1 FAIL on three stores that were perfectly correct
    # (0x4000967C, 0x400095E1, 0x40011020).  A checker whose expectations are
    # copied by hand goes stale the moment the artifact grows -- derive them.
    targets = set()
    for k, v in rs["targets"].items():
        if isinstance(v, list):
            targets.update(v)
        else:
            targets.add(v)

    print("=" * 74)
    print("A. CONTAINER INTEGRITY (re-parsed from the artifact)")
    print("=" * 74)
    d, ds, blocks = parse(VBF)
    for b in blocks:
        want = struct.unpack_from(">H", d, b["crcoff"])[0]
        got = crc16(bytes(d[b["dataoff"]:b["dataoff"] + b["length"]]))
        check("crc16 block 0x%X" % b["start"], want == got,
              "0x%04X" % got)
    m = re.search(rb"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", bytes(d[:ds]))
    want = int(m.group(1), 16)
    got = zlib.crc32(bytes(d[ds:])) & 0xFFFFFFFF
    check("file crc32", want == got, "0x%08X" % got)

    appblk = [b for b in blocks if b["start"] == APP_BASE][0]
    rchw = [b for b in blocks if b["start"] == 0x10000][0]
    flat = bytearray(b"\xFF" * (0x140000 - 0x10000))
    flat[0:rchw["length"]] = d[rchw["dataoff"]:rchw["dataoff"] + rchw["length"]]
    flat[0x20:0x20 + appblk["length"]] = \
        d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]]
    stored = struct.unpack_from(">H", flat, SUM8_AT - 0x10000)[0]
    calc = sum(flat[0:SUM8_AT - 0x10000]) & 0xFFFF
    check("internal sum8 @0x13FFFE", stored == calc, "0x%04X" % calc)

    print()
    print("=" * 74)
    print("B. DIFF vs OEM -- only the expected clusters may differ")
    print("=" * 74)
    od, ods, oblocks = parse(OEM)
    oapp = [b for b in oblocks if b["start"] == APP_BASE][0]
    a = bytes(d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]])
    o = bytes(od[oapp["dataoff"]:oapp["dataoff"] + oapp["length"]])
    diffs = [i for i in range(min(len(a), len(o))) if a[i] != o[i]]
    clusters, cur = [], None
    for i in diffs:
        if cur and i - cur[1] <= 8:
            cur[1] = i
        else:
            if cur:
                clusters.append(cur)
            cur = [i, i]
    if cur:
        clusters.append(cur)
    expect = {info["hook_addr"], info["peek_cave"], info["chain_at"],
              info["rs_cave"], SUM8_AT}
    print("  %d differing bytes in %d clusters:" % (len(diffs), len(clusters)))
    for lo, hi in clusters:
        fa = APP_BASE + lo
        near = min(expect, key=lambda e: abs(e - fa))
        tag = {info["hook_addr"]: "hook", info["peek_cave"]: "peek cave",
               info["chain_at"]: "chain branch", info["rs_cave"]: "rs cave",
               SUM8_AT: "sum8"}.get(near, "?")
        ok = abs(near - fa) < 512
        print("     0x%06X..0x%06X  %4d B  %-13s %s"
              % (fa, APP_BASE + hi, hi - lo + 1, tag,
                 "expected" if ok else "*** UNEXPECTED ***"))
        if not ok:
            fails.append("unexpected diff at 0x%06X" % fa)
    # The chain branch at 0x1181B2 lies INSIDE the peek cave span, so it is not
    # a separate cluster -- expect 4, not 5.  (The first version asserted 5 and
    # FAILED on a correct artifact: the checker was wrong, not the build.
    # AGENTS.md rule 39 -- fix the checker, and fix it UPWARD in strictness.)
    check("all diff clusters accounted for",
          len(clusters) == 4, "%d clusters" % len(clusters))
    # stricter: assert the exact spans, not just the count
    want_spans = [(info["hook_addr"], 4),
                  (info["peek_cave"], info["peek_len"]),
                  (info["rs_cave"], info["rs_len"]),
                  (SUM8_AT, 2)]
    got_spans = [(APP_BASE + lo, hi - lo + 1) for lo, hi in clusters]
    check("diff spans match the build plan exactly",
          got_spans == want_spans,
          " ".join("0x%06X+%d" % s for s in got_spans))
    # and the chain edit must be inside the peek cave cluster
    check("chain branch lies inside the peek-cave cluster",
          info["peek_cave"] <= info["chain_at"]
          < info["peek_cave"] + info["peek_len"],
          "0x%06X" % info["chain_at"])

    print()
    print("=" * 74)
    print("C. RE-DISASSEMBLE THE RS CAVE FROM THE ARTIFACT")
    print("=" * 74)
    project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                        "BCM_C1MCA", False)
    program = None
    try:
        program = project.openProgram("/", "flash_merged.bin", False)
        af = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        listing = program.getListing()
        JB = jpype.JArray(jpype.JByte)

        def A(x):
            return af.getAddress(x)

        cave_addr = info["rs_cave"]
        cave = a[cave_addr - APP_BASE: cave_addr - APP_BASE + info["rs_len"]]
        tid = program.startTransaction("rs-verify")
        try:
            ctxreg = program.getLanguage().getContextBaseRegister()
            pc = program.getProgramContext()
            val = RegisterValue(ctxreg, BigInteger("20000000", 16),
                                BigInteger("FFFFFFFF", 16))
            listing.clearCodeUnits(A(cave_addr),
                                   A(cave_addr + len(cave) - 1), False)
            pc.setRegisterValue(A(cave_addr), A(cave_addr + len(cave)), val)
            mem.setBytes(A(cave_addr),
                         JB([b if b < 128 else b - 256 for b in cave]))
            listing.clearCodeUnits(A(cave_addr),
                                   A(cave_addr + len(cave) - 1), False)
            DisassembleCommand(
                A(cave_addr),
                AddressSet(A(cave_addr), A(cave_addr + len(cave) - 1)),
                True).applyTo(program)

            ins, i = [], listing.getInstructionAt(A(cave_addr))
            while i is not None and i.getAddress().getOffset() < cave_addr + len(cave):
                ins.append(i)
                i = i.getNext()
            print("  %d instructions recovered" % len(ins))

            # ---- V1: every store targets a DECLARED cell ----------------
            base = {}
            bad, stores = [], 0
            first_store_idx = None
            for n, x in enumerate(ins):
                mn = x.getMnemonicString().lower()
                if mn in ("e_lis",):
                    base[str(x.getDefaultOperandRepresentation(0))] = \
                        int(x.getScalar(1).getValue()) << 16
                elif mn in ("e_add16i",):
                    r = str(x.getDefaultOperandRepresentation(0))
                    if r in base:
                        base[r] = (base[r] + int(x.getScalar(2).getValue())) \
                            & 0xFFFFFFFF
                elif mn.startswith(("e_stb", "e_sth", "e_stw", "se_stb",
                                    "se_sth", "se_stw")):
                    stores += 1
                    if first_store_idx is None:
                        first_store_idx = n
                    rr = str(x.getDefaultOperandRepresentation(1))
                    mm = re.search(r"\((r\d+)\)", rr)
                    reg = mm.group(1) if mm else None
                    tgt = base.get(reg)
                    # the frame stores (e_stw r0,0xC(r1)) are ours, skip r1
                    if reg == "r1":
                        continue
                    if tgt not in targets:
                        bad.append((x.getAddress(), str(x), tgt))
            check("V1 every store targets a declared cell",
                  not bad,
                  "%d stores, %d undeclared" % (stores, len(bad)))
            for adr, txt, tgt in bad:
                print("       *** %s  %s  -> %s"
                      % (adr, txt, hex(tgt) if tgt else "unresolved"))

            # V1b -- strictness UP: the depth-4 cells must actually be written,
            # not merely permitted.  A loosened check that only forbids unknown
            # targets would pass an artifact where depth 4 stores nothing.
            want_written = {rs["targets"]["substate"], rs["targets"]["flag"]}
            got_written = set()
            base2 = {}
            for x in ins:
                mn = x.getMnemonicString().lower()
                d0 = str(x.getDefaultOperandRepresentation(0))
                if mn == "e_lis":
                    base2[d0] = int(x.getScalar(1).getValue()) << 16
                elif mn == "e_add16i":
                    r = str(x.getDefaultOperandRepresentation(1))
                    if r in base2:
                        base2[d0] = (base2[r]
                                     + int(x.getScalar(2).getValue())) & 0xFFFFFFFF
                elif mn.startswith(("e_stb", "e_sth", "e_stw")):
                    rr = str(x.getDefaultOperandRepresentation(1))
                    mm = re.search(r"\((r\d+)\)", rr)
                    if mm and base2.get(mm.group(1)) in want_written:
                        got_written.add(base2[mm.group(1)])
            check("V1b depth-4 cells are actually written",
                  got_written == want_written,
                  " ".join(hex(a) for a in sorted(got_written)))

            # V1c -- depth 5's ANNOUNCE must write 0xFF, not 1.  This is the
            # entire point of depth 5: 0x40003F53 is a Volcano dirty-flag byte
            # and the RS consumer tests mask 0x20 (n=2).  Depth 2 wrote 1
            # (bit index 7), which no consumer reads -- the code then persists
            # for minutes and nothing fires.  Assert the VALUE, not just the
            # target, or a regression to 1 would pass V1 silently.
            want_v = rs["targets"]["rke_valid"]
            ann = []
            b3 = {}
            for x in ins:
                mn = x.getMnemonicString().lower()
                d0 = str(x.getDefaultOperandRepresentation(0))
                if mn == "e_lis":
                    b3[d0] = int(x.getScalar(1).getValue()) << 16
                elif mn == "e_add16i":
                    r = str(x.getDefaultOperandRepresentation(1))
                    if r in b3:
                        b3[d0] = (b3[r] + int(x.getScalar(2).getValue())) & 0xFFFFFFFF
                elif mn in ("e_li", "se_li"):
                    sc = x.getScalar(x.getNumOperands() - 1)
                    if sc is not None:
                        b3["#" + d0] = int(sc.getValue())
                elif mn.startswith(("e_stb", "se_stb")):
                    rr = str(x.getDefaultOperandRepresentation(1))
                    mm = re.search(r"\((r\d+)\)", rr)
                    src = str(x.getDefaultOperandRepresentation(0))
                    if mm and b3.get(mm.group(1)) == want_v:
                        ann.append(b3.get("#" + src))
            check("V1c depth-5 announce writes 0xFF to the dirty flag",
                  0xFF in ann,
                  "values stored to %s: %s" % (hex(want_v), ann))

            # ---- V2: no store before the first MAGIC compare ------------
            first_cmp = next((n for n, x in enumerate(ins)
                              if x.getMnemonicString().lower().startswith("e_cmpl16i")),
                             None)
            check("V2 no store precedes the first MAGIC compare",
                  first_cmp is not None and (first_store_idx is None
                                             or first_store_idx > first_cmp),
                  "cmp@%s store@%s" % (first_cmp, first_store_idx))

            # ---- V3: the MAGICs are the hardware-proven-free ones -------
            found = sorted({int(x.getScalar(1).getValue()) & 0xFFFF
                            for x in ins
                            if x.getMnemonicString().lower().startswith("e_cmpl16i")})
            check("V3 MAGICs match the hardware-probed free set",
                  found == sorted(FREE_MAGICS),
                  " ".join("0x%04X" % v for v in found))

            # ---- V4: the chain is closed --------------------------------
            tail = ins[-1]
            check("V4 rs tail returns to stock 0x%06X" % rs["ret"],
                  ("%x" % rs["ret"]) in str(tail).lower(), str(tail))
            chain_b = a[info["chain_at"] - APP_BASE:
                        info["chain_at"] - APP_BASE + 4]
            check("V4 peek tail chains into the rs cave",
                  bytes(chain_b) == bytes(rs["peek_tail_new"]),
                  chain_b.hex().upper())
        finally:
            program.endTransaction(tid, False)
    finally:
        try:
            if program is not None:
                project.close()
        except Exception:
            pass

    print()
    print("=" * 74)
    if fails:
        print("RESULT: %d CHECK(S) FAILED -- DO NOT FLASH" % len(fails))
        for f in fails:
            print("   - %s" % f)
    else:
        print("RESULT: ALL CHECKS PASSED")
        print("  artifact: %s" % VBF)
        print("  sha256  : %s" % info["sha256"])
        print("\n  ⚠ This build can start an engine from a CAN message.")
        print("    docs/rs_trigger_design.md Sec.1 before flashing.")
    print("=" * 74)
    return 1 if fails else 0


try:
    rc = main()
except Exception:
    traceback.print_exc()
    rc = 2
finally:
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
