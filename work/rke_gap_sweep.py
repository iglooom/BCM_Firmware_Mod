"""Close the last two gaps found by the RM sweep.

GAP 1 - eMIOS_1 channel 25 (PF12).
  PSMI PADSEL51 resets to 00 = PCR[92] = PF12, so PF12 is the DEFAULT source for
  eMIOS_1 channel 25 without firmware writing anything. The earlier audit only
  said "runtime consumers use channels {0,8,16,23,24}". That is a consumer
  argument; the load-bearing question is whether channel 25's own registers are
  ENABLED. eMIOS_1 base 0xC3FA4000, channel n registers at base + 0x20 + n*0x20:
      CADR(+0x00) CBDR(+0x04) CCNTR(+0x08) CCR(+0x0C) CSR(+0x10)
  Channel 25 -> 0xC3FA4000 + 0x20 + 25*0x20 = 0xC3FA4360 .. 0xC3FA4373.
  CCR bits: MODE=[6:0]; MODE==0 means the channel is DISABLED.

GAP 2 - peripherals never swept at all.
  Sweep EVERY peripheral window from the RM memory map and report which ones the
  firmware actually touches, so no input-capable block is left unexamined
  (notably CAN sampler @0xFFE70000, I2C_0, DSPI_0..5, MPU, SSCM).

Read-only.
"""
import json
import os
import struct
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()
periphs = json.load(open(ROOT + "/work/rm_periph_map.json"))

EMIOS1 = 0xC3FA4000
CH25 = EMIOS1 + 0x20 + 25 * 0x20
CH25_REGS = {CH25 + 0x00: "CADR25", CH25 + 0x04: "CBDR25", CH25 + 0x08: "CCNTR25",
             CH25 + 0x0C: "CCR25", CH25 + 0x10: "CSR25"}

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    LD = {"e_lbz", "e_lhz", "e_lwz", "lbz", "lhz", "lwz", "se_lwz", "se_lbz", "se_lhz"}
    ST = {"e_stb", "e_sth", "e_stw", "stb", "sth", "stw", "se_stw", "se_stb", "se_sth"}
    LSX = {"e_lwzx", "lwzx", "e_stwx", "stwx", "e_lbzx", "lbzx",
           "e_stbx", "stbx", "e_lhzx", "lhzx", "e_sthx", "sthx"}

    def isreg(o):
        return o.__class__.__name__.endswith(".Register")

    def issc(o):
        return o.__class__.__name__.endswith(".Scalar")

    def opparse(ins):
        base, disp = None, 0
        for oi in range(ins.getNumOperands()):
            objs = list(ins.getOpObjects(oi))
            rs = [o for o in objs if isreg(o)]
            sc = [o for o in objs if issc(o)]
            if rs and sc:
                base, disp = rs[0].getName(), sc[0].getSignedValue()
            elif rs and oi > 0 and base is None:
                base = rs[0].getName()
        return base, disp

    resolved = []      # (ea, site, func, mnem, storeval)
    idx_bases = []
    for f in fm.getFunctions(True):
        val = {}
        for ins in listing.getInstructions(f.getBody(), True):
            mn = ins.getMnemonicString()
            try:
                if mn in ("e_lis", "lis"):
                    rd, sc = ins.getRegister(0), ins.getScalar(1)
                    if rd and sc is not None:
                        val[rd.getName()] = (sc.getUnsignedValue() & 0xFFFF) << 16
                elif mn in ("e_li", "li", "se_li"):
                    rd, sc = ins.getRegister(0), ins.getScalar(1)
                    if rd and sc is not None:
                        val[rd.getName()] = sc.getSignedValue() & 0xFFFFFFFF
                elif mn in ("e_add16i", "e_addi", "addi", "se_addi"):
                    regs = [ins.getRegister(k) for k in range(ins.getNumOperands())
                            if ins.getRegister(k)]
                    sc = None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None:
                            sc = ins.getScalar(k)
                    if regs and sc is not None:
                        rd = regs[0].getName()
                        rs = regs[1].getName() if len(regs) > 1 else rd
                        if rs in val:
                            val[rd] = (val[rs] + sc.getSignedValue()) & 0xFFFFFFFF
                        else:
                            val.pop(rd, None)
                elif mn in ("e_or2i", "oris", "ori"):
                    rd = ins.getRegister(0)
                    sc = None
                    for k in range(ins.getNumOperands()):
                        if ins.getScalar(k) is not None:
                            sc = ins.getScalar(k)
                    if rd and sc is not None and rd.getName() in val:
                        val[rd.getName()] |= sc.getUnsignedValue()
                elif mn in LSX:
                    for k in range(ins.getNumOperands()):
                        r = ins.getRegister(k)
                        if r is None:
                            continue
                        b = val.get(r.getName())
                        if b is not None and b >= 0xC3F00000:
                            idx_bases.append((b, str(ins.getAddress()), f.getName(), mn))
                elif mn in LD | ST:
                    base, disp = opparse(ins)
                    if base in val:
                        ea = (val[base] + disp) & 0xFFFFFFFF
                        if ea >= 0xC3F00000:
                            sv = None
                            if mn in ST:
                                rs = ins.getRegister(0)
                                if rs is not None:
                                    sv = val.get(rs.getName())
                            resolved.append((ea, str(ins.getAddress()),
                                             f.getName(), mn, sv))
            except Exception:
                pass
finally:
    project.close()

# ---------- GAP 1: eMIOS_1 channel 25 ------------------------------------
print("=" * 78)
print("GAP 1: eMIOS_1 channel 25 (PF12 is its PSMI reset-default source)")
print("=" * 78)
print("  channel-25 register block: 0x%08X .. 0x%08X" % (CH25, CH25 + 0x1F))
ch25_hits = [r for r in resolved if CH25 <= r[0] <= CH25 + 0x1F]
print("\n  [code] resolved accesses to channel-25 registers: %d" % len(ch25_hits))
for ea, site, fn, mn, sv in ch25_hits:
    print("     @%s [%s] %-8s %s%s" % (site, fn, mn, CH25_REGS.get(ea, hex(ea)),
                                       "  value=0x%08X" % sv if sv is not None else ""))
if not ch25_hits:
    print("     (none - CCR25 never written, so MODE stays 0 = channel DISABLED)")

for a, nm in sorted(CH25_REGS.items()):
    n = raw.count(struct.pack(">I", a))
    print("  [literal] %-8s 0x%08X occurrences in image: %d" % (nm, a, n))

emios1_all = sorted({r[0] for r in resolved if EMIOS1 <= r[0] < EMIOS1 + 0x4000})
print("\n  all resolved eMIOS_1 register addresses (%d):" % len(emios1_all))
for ea in emios1_all:
    off = ea - EMIOS1
    ch = (off - 0x20) // 0x20 if off >= 0x20 else None
    print("     0x%08X (+0x%03X)%s" % (ea, off,
          "  -> channel %d" % ch if ch is not None and 0 <= ch < 32 else ""))

# ---------- GAP 2: full peripheral sweep ---------------------------------
print("\n" + "=" * 78)
print("GAP 2: which peripherals does the firmware touch at all?")
print("=" * 78)
print("  %-14s %-22s %s" % ("base", "peripheral", "resolved accesses"))
print("  " + "-" * 62)
for p in periphs:
    s, e, nm = p["start"], p["end"], p["name"]
    if e is None or s < 0xC3F00000 or nm.startswith("Reserved") or nm.startswith("Mirrored"):
        continue
    n = sum(1 for r in resolved if s <= r[0] <= e)
    ni = sum(1 for b in idx_bases if s <= b[0] <= e)
    flag = ""
    if n == 0 and ni == 0:
        flag = "   <- never touched"
    print("  0x%08X   %-22s %d%s%s"
          % (s, nm, n, ("  (+%d indexed)" % ni) if ni else "", flag))
