"""SIUL PSMI (Pad Selection for Multiplexed Inputs) audit - the "via some mux" route.

WHY THIS IS A REAL GAP
----------------------
PSMI is the documented SIUL mechanism by which a PERIPHERAL INPUT is sourced from
one of several possible pads. Every previous audit asked "does firmware touch
PI15's own registers?" - but with PSMI the pad is never named by its own PCR/GPDI
address at all: the peripheral is simply told which pad to listen to. That is
exactly the "configured via some mux" path.

RM0037 (SPC560B64) Table 182, SIUL offsets 0x0500-0x053C (16 x 32-bit registers,
each holding four 8-bit PADSEL fields; PADSELn is at byte offset 0x500+n):

  PADSEL37 @0x525  CS0_4 / DSPI_4    00:PCR[107] 01:PCR[123] 10:PCR[134] 11:PCR[143]  <- PI15
  PADSEL51 @0x533  E1UC[25]/eMIOS_1  00:PCR[92]  01:PCR[124]                          <- PF12

NOTE PADSEL51 default: value 00 selects PCR[92] = PF12. So PF12 is the RESET
DEFAULT source for eMIOS_1 channel 25 - it is "selected" even if firmware never
writes PSMI at all. Whether that matters depends entirely on whether eMIOS_1
ch25 is enabled (previously shown: runtime consumers use only ch {0,8,16,23,24}).

Caveat on PI15: CS0_4 is a chip-select OUTPUT, so even if PADSEL37=11 it cannot
carry a button state into the MCU.

This script checks whether firmware writes the PSMI block at all. Read-only.
"""
import os
import struct
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()

SIU = 0xC3F90000
PSMI_LO, PSMI_HI = SIU + 0x500, SIU + 0x540

TARGETS = {
    0x525: ("PADSEL37", "CS0_4/DSPI_4", {0: "PCR107", 1: "PCR123",
                                         2: "PCR134", 3: "PCR143 = PI15"}),
    0x533: ("PADSEL51", "E1UC[25]/eMIOS_1", {0: "PCR92 = PF12", 1: "PCR124"}),
}

print("=" * 78)
print("SIUL PSMI audit  (0x%08X..0x%08X)" % (PSMI_LO, PSMI_HI - 1))
print("=" * 78)
for off, (nm, fn, opts) in TARGETS.items():
    reg = SIU + (off & ~3)
    print("\n  %s @SIU+0x%03X  (%s)" % (nm, off, fn))
    print("    containing 32-bit register: 0x%08X (PSMI%d_%d)"
          % (reg, ((off - 0x500) & ~3), ((off - 0x500) & ~3) + 3))
    for v, p in sorted(opts.items()):
        print("      %s: %s" % (format(v, "02b"), p))

# ---- literal scan over the PSMI window ----------------------------------
lits = []
for i in range(len(raw) - 3):
    v = struct.unpack_from(">I", raw, i)[0]
    if PSMI_LO <= v < PSMI_HI:
        lits.append((i, v))
print("\n[1] PSMI addresses present as 32-bit literals: %d" % len(lits))
for o, v in lits[:20]:
    print("    @0x%06X -> 0x%08X (SIU+0x%03X)" % (o, v, v - SIU))
if not lits:
    print("    (none)")

# ---- constant-propagating resolve ---------------------------------------
project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    LD = {"e_lbz", "e_lhz", "e_lwz", "lbz", "lhz", "lwz", "se_lwz", "se_lbz", "se_lhz"}
    ST = {"e_stb", "e_sth", "e_stw", "stb", "sth", "stw", "se_stw", "se_stb", "se_sth"}

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

    hits = []
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
                elif mn in LD | ST:
                    base, disp = opparse(ins)
                    if base in val:
                        ea = (val[base] + disp) & 0xFFFFFFFF
                        if PSMI_LO <= ea < PSMI_HI:
                            sv = None
                            if mn in ST:
                                rs = ins.getRegister(0)
                                if rs is not None:
                                    sv = val.get(rs.getName())
                            hits.append((str(ins.getAddress()), f.getName(), mn, ea, sv))
            except Exception:
                pass

    print("\n[2] PSMI accesses resolved by constant propagation: %d" % len(hits))
    for site, fn, mn, ea, sv in hits:
        print("    @%s [%s] %-8s SIU+0x%03X%s"
              % (site, fn, mn, ea - SIU,
                 "  value=0x%08X" % sv if sv is not None else ""))
    if not hits:
        print("    (none - PSMI block never written; all PADSEL fields stay at")
        print("     their reset value of 0)")
finally:
    project.close()

print("\n" + "=" * 78)
print("INTERPRETATION")
print("=" * 78)
print("If PSMI is never written, every PADSEL = 0 (reset).")
print("  PADSEL37 = 00 -> CS0_4 sourced from PCR107, NOT PCR143/PI15.")
print("  PADSEL51 = 00 -> E1UC[25] sourced from PCR92 = PF12 (reset default),")
print("                   but that only matters if eMIOS_1 ch25 is enabled.")
