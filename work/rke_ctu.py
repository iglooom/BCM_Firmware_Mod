"""Does the CTU (Cross Triggering Unit) sample PI15 = ADC0_S[23] = abs channel 55?

WHY THIS IS NOT COVERED BY THE NCMR TEST
----------------------------------------
CTU-triggered conversions do NOT go through NCMR. The CTU has its own Event
Configuration Registers (CTU_EVTCFGR0..63) that each name an ADC channel and
trigger it directly, and results can be read back from the CTU/ADC without the
normal-conversion mask ever mentioning the channel. So an NCMR-only audit can
miss a CTU-sampled pin entirely. Same blind spot as the eDMA case.

SPC560B64: CTU base 0xFFE6_4000 .. 0xFFE6_7FFF (16 KB),
           EVTCFGR0..63 at offsets 0x030..0x12C (4 bytes each).

Approach:
  [1] raw literal scan of the whole CTU window (catches table/pointer use)
  [2] constant-propagating resolve of loads/stores into the CTU window
      (catches e_lis+e_add16i formed bases, which literals miss)
  [3] if any EVTCFGR is written, decode the channel it selects
  [4] ADC MCR CTU-enable bit check (the ADC side must also enable CTU trigger)

Read-only.
"""
import os
import struct
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()

CTU_LO, CTU_HI = 0xFFE64000, 0xFFE68000
EVT_LO, EVT_HI = 0x030, 0x130          # EVTCFGR0..63
PI15_CH = 55

print("=" * 78)
print("CTU audit  base 0xFFE64000..0xFFE67FFF ; target = abs ADC channel %d (PI15)" % PI15_CH)
print("=" * 78)

# ---- [1] raw literal scan ------------------------------------------------
lits = []
for i in range(len(raw) - 3):
    v = struct.unpack_from(">I", raw, i)[0]
    if CTU_LO <= v < CTU_HI:
        lits.append((i, v))
print("\n[1] CTU-window addresses present as 32-bit literals: %d" % len(lits))
for off, v in lits[:40]:
    r = v - CTU_LO
    nm = ("EVTCFGR%d" % ((r - 0x030) // 4)) if EVT_LO <= r < EVT_HI else "+0x%X" % r
    print("    @0x%06X -> 0x%08X  CTU.%s" % (off, v, nm))
if not lits:
    print("    (none)")

# ---- [2] constant-propagating resolve ------------------------------------
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

    ctu_hits, adc_mcr, indexed = [], [], []
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
                        if b is not None and CTU_LO <= b < CTU_HI:
                            indexed.append((str(ins.getAddress()), f.getName(), mn, b))
                elif mn in LD | ST:
                    base, disp = opparse(ins)
                    if base in val:
                        ea = (val[base] + disp) & 0xFFFFFFFF
                        sv = None
                        if mn in ST:
                            rs = ins.getRegister(0)
                            if rs is not None:
                                sv = val.get(rs.getName())
                        if CTU_LO <= ea < CTU_HI:
                            ctu_hits.append((str(ins.getAddress()), f.getName(),
                                             mn, ea, sv))
                        if ea in (0xFFE00000, 0xFFE04000):
                            adc_mcr.append((str(ins.getAddress()), f.getName(),
                                            mn, ea, sv))
            except Exception:
                pass

    print("\n[2] CTU accesses resolved by constant propagation: %d" % len(ctu_hits))
    for site, fn, mn, ea, sv in ctu_hits:
        r = ea - CTU_LO
        nm = ("EVTCFGR%d" % ((r - 0x030) // 4)) if EVT_LO <= r < EVT_HI else "+0x%X" % r
        print("    @%s [%s] %-8s CTU.%-12s%s"
              % (site, fn, mn, nm, "  value=0x%08X" % sv if sv is not None else ""))
    if not ctu_hits:
        print("    (none - CTU is never read or written)")

    print("\n[3] indexed CTU accesses: %d" % len(indexed))
    for site, fn, mn, b in indexed:
        print("    @%s [%s] %s base 0x%08X" % (site, fn, mn, b))
    if not indexed:
        print("    (none)")

    print("\n[4] ADC MCR accesses (CTU trigger must be enabled ADC-side too)")
    for site, fn, mn, ea, sv in adc_mcr:
        print("    @%s [%s] %-8s ADC%d.MCR%s"
              % (site, fn, mn, 0 if ea == 0xFFE00000 else 1,
                 "  value=0x%08X" % sv if sv is not None else "  (value from reg)"))
    if not adc_mcr:
        print("    (none resolved)")
finally:
    project.close()

print("\nCONCLUSION GUIDE: CTU can only sample a pad if (a) some EVTCFGR names that")
print("ADC channel AND (b) the CTU registers are actually written. Zero CTU accesses")
print("means the peripheral is left in reset and cannot trigger any conversion.")
