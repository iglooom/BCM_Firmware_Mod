"""Decisive ADC test: resolve actual ADC register accesses (constant-propagating,
so a base built with e_lis+e_add16i is seen) and recover the NCMR/JCMR/DMAE
values the firmware really programs.

A channel is ARMED BY A BITMASK, not an address, so this is the only test that
can rule PI15 (ADC0_S[23] = absolute channel 55) in or out:
    channel 55 -> NCMR1 / JCMR1 / CIMR1 / DMAR1 bit (55-32)=23 -> mask 0x00800000

Also enumerates ADC DMA enables (DMAE/DMAR) to close the eDMA path, which leaves
no CDR read behind. Read-only.
"""
import os
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
ADC0, ADC1 = 0xFFE00000, 0xFFE04000
PI15_CH = 55
PI15_BIT = PI15_CH - 32          # 23 within the *1 registers
PI15_MASK = 1 << PI15_BIT        # 0x00800000

REG = {0x00: "MCR", 0x04: "MSR", 0x10: "ISR", 0x20: "IMR",
       0x24: "CIMR0", 0x28: "CIMR1", 0x2C: "CIMR2",
       0x40: "DMAE", 0x44: "DMAR0", 0x48: "DMAR1", 0x4C: "DMAR2",
       0x94: "CTR0", 0x98: "CTR1", 0x9C: "CTR2",
       0xA4: "NCMR0", 0xA8: "NCMR1", 0xAC: "NCMR2",
       0xB4: "JCMR0", 0xB8: "JCMR1", 0xBC: "JCMR2"}
for i in range(16):
    REG[0x100 + 4 * i] = "CDR%d" % i
for i in range(32, 60):
    REG[0x180 + 4 * (i - 32)] = "CDR%d" % i

MASKREGS = {"NCMR0", "NCMR1", "NCMR2", "JCMR0", "JCMR1", "JCMR2",
            "CIMR0", "CIMR1", "CIMR2", "DMAR0", "DMAR1", "DMAR2", "DMAE"}

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    LD = {"e_lbz", "e_lhz", "e_lwz", "lbz", "lhz", "lwz", "se_lwz", "se_lbz", "se_lhz"}
    ST = {"e_stb", "e_sth", "e_stw", "stb", "sth", "stw", "se_stw", "se_stb", "se_sth"}
    LSX = {"e_lwzx", "lwzx", "e_stwx", "stwx", "e_lbzx", "lbzx", "e_stbx", "stbx",
           "e_lhzx", "lhzx", "e_sthx", "sthx"}

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
    indexed = []
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
                        if b is not None and ADC0 <= b < ADC1 + 0x4000:
                            indexed.append((str(ins.getAddress()), f.getName(), mn, b))
                elif mn in LD | ST:
                    base, disp = opparse(ins)
                    if base in val:
                        ea = (val[base] + disp) & 0xFFFFFFFF
                        if ADC0 <= ea < ADC1 + 0x4000:
                            unit = 0 if ea < ADC1 else 1
                            off = ea - (ADC0 if unit == 0 else ADC1)
                            name = REG.get(off, "+0x%X" % off)
                            # try to capture the stored value from a nearby li/lis
                            sv = None
                            if mn in ST:
                                rs = ins.getRegister(0)
                                if rs is not None:
                                    sv = val.get(rs.getName())
                            hits.append((str(ins.getAddress()), f.getName(), mn,
                                         unit, name, ea, sv))
            except Exception:
                pass

    print("=" * 80)
    print("PI15 = ADC0_S[23] = absolute channel %d -> *1 register bit %d, mask 0x%08X"
          % (PI15_CH, PI15_BIT, PI15_MASK))
    print("=" * 80)

    print("\n[A] resolved ADC register accesses")
    if not hits:
        print("    (none resolved)")
    for site, fn, mn, unit, name, ea, sv in hits:
        extra = ""
        if sv is not None:
            extra = "  value=0x%08X" % sv
            if name in MASKREGS and name.endswith("1") and (sv & PI15_MASK):
                extra += "   <<< PI15 BIT SET!"
        print("    @%s [%s] %-8s ADC%d.%-7s (0x%08X)%s"
              % (site, fn, mn, unit, name, ea, extra))

    print("\n[B] mask/DMA register touches only")
    mrs = [h for h in hits if h[4] in MASKREGS]
    if not mrs:
        print("    (none - NCMR/JCMR/CIMR/DMAE/DMAR never written with a resolvable base)")
    for site, fn, mn, unit, name, ea, sv in mrs:
        print("    @%s [%s] %-8s ADC%d.%-7s%s"
              % (site, fn, mn, unit, name,
                 "  value=0x%08X" % sv if sv is not None else "  (value from reg/table)"))

    print("\n[C] indexed ADC accesses (dynamic channel addressing)")
    if not indexed:
        print("    (none)")
    for site, fn, mn, b in indexed:
        print("    @%s [%s] %s base 0x%08X" % (site, fn, mn, b))
finally:
    project.close()
