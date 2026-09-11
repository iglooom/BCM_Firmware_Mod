"""Which eMIOS channels does this firmware actually enable? (= PWM output pins)

Resolves every eMIOS access (constant-propagating, both modules) and buckets by
hardware channel, using the RM layout: channel n block = base + 0x20 + n*0x20,
with CADR+0x00 CBDR+0x04 CCNTR+0x08 CCR+0x0C CSR+0x10.

A channel is only a real output if its CCR is written with a non-zero MODE.
Also resolves the generic-driver group bases (0xC3FA0020/0120/0220/0320 and the
eMIOS_1 equivalents) that FUN_0003f836 dispatches to.

Read-only.
"""
import os
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
E0, E1 = 0xC3FA0000, 0xC3FA4000
REGN = {0x00: "CADR", 0x04: "CBDR", 0x08: "CCNTR", 0x0C: "CCR", 0x10: "CSR"}

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
                        if E0 <= ea < E1 + 0x4000:
                            sv = None
                            if mn in ST:
                                rs = ins.getRegister(0)
                                if rs is not None:
                                    sv = val.get(rs.getName())
                            hits.append((ea, str(ins.getAddress()), f.getName(),
                                         mn, sv))
            except Exception:
                pass
finally:
    project.close()

print("=" * 78)
print("eMIOS accesses resolved: %d" % len(hits))
print("=" * 78)
for mod, base in (("eMIOS_0", E0), ("eMIOS_1", E1)):
    sub = [h for h in hits if base <= h[0] < base + 0x4000]
    chans = {}
    glob_ = []
    for ea, site, fn, mn, sv in sub:
        off = ea - base
        if off < 0x20:
            glob_.append((off, site, fn, mn, sv))
        else:
            ch = (off - 0x20) // 0x20
            chans.setdefault(ch, []).append(((off - 0x20) % 0x20, site, fn, mn, sv))
    print("\n  %s  global regs: %s" % (mod, sorted({g[0] for g in glob_}) or "none"))
    print("  %s  channels touched: %s" % (mod, sorted(chans) or "none"))
    for ch in sorted(chans):
        regs = sorted({REGN.get(r, "+0x%X" % r) for r, _, _, _, _ in chans[ch]})
        wrote_ccr = [x for x in chans[ch] if x[0] == 0x0C and x[3] in ST]
        note = ""
        if wrote_ccr:
            vals = {x[4] for x in wrote_ccr if x[4] is not None}
            note = "  CCR WRITTEN %s" % ([hex(v) for v in vals] if vals else "(dyn)")
        print("     ch%-3d %-28s%s" % (ch, ",".join(regs), note))

print("\nNOTE: eMIOS group/master-bus channels are 0,8,16,24 per module; a channel")
print("only drives a pin if its CCR MODE field is non-zero.")
