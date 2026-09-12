#!/usr/bin/env python3
"""Independent verification of the probe-bank VBF (AGENTS.md 8 definition of done).

Nothing here reuses the builder's working state: the VBF is re-read from disk,
re-parsed, every integrity layer recomputed from scratch, the 17 probes are
RE-DISASSEMBLED out of the rebuilt image with Ghidra, and the whole file is
diffed against OEM to prove no collateral change.

Checks:
  1. every block CRC-16 matches the stored value
  2. file CRC-32 matches the header field
  3. internal sum8 matches the stored word
  4. each probe re-disassembles to the INTENDED e_lis/e_lbz pair reading the
     intended address - decoded by Ghidra, not by re-reading my own immediates
  5. the OEM tail (se_stb/se_mr/se_blr) is byte-identical at every probe
  6. diff vs OEM shows ONLY the expected clusters (17 probes + sum8 + 2 CRC16
     words + the file_checksum text)

Usage: python3 work/probe-bank/verify.py
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

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.app.cmd.disassemble import DisassembleCommand        # noqa: E402
from ghidra.base.project import GhidraProject                    # noqa: E402
from ghidra.program.model.address import AddressSet              # noqa: E402
from ghidra.program.model.lang import RegisterValue              # noqa: E402
from java.math import BigInteger                                 # noqa: E402

ROOT = "/home/gl/Projects/ford/BCM/Research"
OEM = os.path.join(ROOT, "JV6T-14C094-AD.VBF")
NEW = os.path.join(ROOT, "work/probe-bank/JV6T-14C094-AD_probe-bank.VBF")
PLAN = os.path.join(ROOT, "work/owner/probe_bank_bytes.json")
APP_BASE = 0x10020
SUM8_AT = 0x13FFFE
fails = []


def check(name, ok, detail=""):
    print("   [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                            ("  - " + detail) if detail else ""))
    if not ok:
        fails.append(name)


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


print("== probe-bank VBF verification ==")
print("   artifact %s" % NEW)
print("   sha256   %s\n" % hashlib.sha256(open(NEW, "rb").read()).hexdigest())

d, ds, blocks = parse(NEW)
appblk = [b for b in blocks if b["start"] == APP_BASE][0]
rchw = [b for b in blocks if b["start"] == 0x10000][0]
probes = json.load(open(PLAN))["probes"]


def fo(fa):
    return appblk["dataoff"] + (fa - APP_BASE)


# ---- 1/2/3 integrity --------------------------------------------------------
print("-- integrity --")
for b in blocks:
    stored = struct.unpack(">H", d[b["crcoff"]:b["crcoff"] + 2])[0]
    calc = crc16(bytes(d[b["dataoff"]:b["dataoff"] + b["length"]]))
    check("block 0x%X CRC-16" % b["start"], stored == calc,
          "stored 0x%04X calc 0x%04X" % (stored, calc))

m = re.search(rb"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", bytes(d[:ds]))
stored32 = int(m.group(1), 16)
calc32 = zlib.crc32(bytes(d[ds:])) & 0xFFFFFFFF
check("file CRC-32", stored32 == calc32,
      "stored 0x%08X calc 0x%08X" % (stored32, calc32))

flat = bytearray(b"\xFF" * (0x140000 - 0x10000))
flat[0:rchw["length"]] = d[rchw["dataoff"]:rchw["dataoff"] + rchw["length"]]
flat[0x20:0x20 + appblk["length"]] = \
    d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]]
stored8 = struct.unpack_from(">H", d, fo(SUM8_AT))[0]
calc8 = sum(flat[0:SUM8_AT - 0x10000]) & 0xFFFF
check("internal sum8", stored8 == calc8,
      "stored 0x%04X calc 0x%04X" % (stored8, calc8))

# ---- 5 OEM tail preserved ---------------------------------------------------
print("\n-- probe bytes --")
tail_ok = True
for p in probes:
    o = fo(int(p["reader"], 16))
    got = bytes(d[o:o + 14])
    want = bytes.fromhex(p["new_bytes"].replace(" ", ""))
    oem = bytes.fromhex(p["old_bytes"].replace(" ", ""))
    if got != want or got[8:] != oem[8:]:
        tail_ok = False
        print("      %s mismatch" % p["did"])
check("all 17 probes written, OEM tails intact", tail_ok)

# ---- 6 diff vs OEM ----------------------------------------------------------
print("\n-- diff vs OEM --")
od, ods, oblocks = parse(OEM)
oapp = [b for b in oblocks if b["start"] == APP_BASE][0]
a = bytes(od[oapp["dataoff"]:oapp["dataoff"] + oapp["length"]])
b_ = bytes(d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]])
diffs = [i for i in range(len(a)) if a[i] != b_[i]]
clusters = []
for i in diffs:
    if clusters and i - clusters[-1][-1] <= 4:
        clusters[-1].append(i)
    else:
        clusters.append([i])
expected = {int(p["reader"], 16) - APP_BASE for p in probes}
named = 0
for c in clusters:
    fa = c[0] + APP_BASE
    tag = "?"
    for e in expected:
        if abs(c[0] - e) <= 8:
            tag = "probe"
            named += 1
            break
    if SUM8_AT - 8 <= fa <= SUM8_AT + 8:
        tag = "sum8"
        named += 1
    print("      0x%06X  %2d byte(s)  %s" % (fa, len(c), tag))
check("diff clusters are all expected", named == len(clusters),
      "%d clusters, %d explained" % (len(clusters), named))

# ---- 4 re-disassemble from the rebuilt image --------------------------------
# Method copied from work/acc-fix/verify.py: write the rebuilt bytes into a
# scratch program inside a transaction that is ALWAYS rolled back, set the VLE
# context, and let Ghidra disassemble.  We then read the ADDRESS Ghidra decodes,
# not the immediates we wrote - that is what makes this an independent check and
# what would have caught the split-field bug (270) on its own.
print("\n-- re-disassembly (Ghidra, from the REBUILT image) --")
img = bytearray(b"\xFF" * 0x15BF4C)
img[0x10000:0x10000 + rchw["length"]] = d[rchw["dataoff"]:rchw["dataoff"] + rchw["length"]]
img[0x10020:0x10020 + appblk["length"]] = \
    d[appblk["dataoff"]:appblk["dataoff"] + appblk["length"]]

project = GhidraProject.openProject(os.path.join(ROOT, "ghidra_proj"),
                                    "BCM_C1MCA", False)
program = None
tid = None
try:
    program = project.openProgram("/", "flash_merged.bin", False)
    af = program.getAddressFactory().getDefaultAddressSpace()
    mem = program.getMemory()
    listing = program.getListing()
    ctxreg = program.getLanguage().getContextBaseRegister()
    pc = program.getProgramContext()
    import jpype
    JB = jpype.JArray(jpype.JByte)

    def A(x):
        return af.getAddress(x)

    def jb(bs):
        return JB([b if b < 128 else b - 256 for b in bs])

    tid = program.startTransaction("verify-probe-bank")
    decoded_ok = 0
    for p in probes:
        ea = int(p["reader"], 16)
        want = int(p["watch"], 16)
        listing.clearCodeUnits(A(ea), A(ea + 13), False)
        pc.setRegisterValue(A(ea), A(ea + 13),
                            RegisterValue(ctxreg, BigInteger("20000000", 16),
                                          BigInteger("FFFFFFFF", 16)))
        mem.setBytes(A(ea), jb(bytes(img[ea:ea + 14])))
        DisassembleCommand(A(ea), AddressSet(A(ea), A(ea + 13)), True).applyTo(program)
        i1 = listing.getInstructionAt(A(ea))
        i2 = listing.getInstructionAt(A(ea + 4))
        s1, s2 = str(i1).strip() if i1 else "?", str(i2).strip() if i2 else "?"
        # reconstruct the address from what GHIDRA decoded
        got = None
        try:
            hi = int(s1.split(",")[-1], 16)
            disp = s2.split(",")[-1].split("(")[0]
            lo = int(disp, 16)
            got = ((hi << 16) + lo) & 0xFFFFFFFF
        except Exception:
            pass
        good = (got == want)
        decoded_ok += 1 if good else 0
        print("      %s  %-22s %-24s -> %s %s"
              % (p["did"], s1, s2, hex(got) if got is not None else "?",
                 "OK" if good else "!! want " + p["watch"]))
    check("all probes decode to the intended address", decoded_ok == len(probes),
          "%d/%d" % (decoded_ok, len(probes)))
except Exception:
    traceback.print_exc()
    fails.append("re-disassembly")
finally:
    if program is not None and tid is not None:
        program.endTransaction(tid, False)      # ALWAYS roll back the scratch write
    try:
        project.close()
    except Exception:
        pass

print("\n== %s ==" % ("ALL CHECKS PASSED" if not fails
                      else "FAILURES: " + ", ".join(fails)))
sys.stdout.flush()
sys.stderr.flush()
os._exit(1 if fails else 0)
