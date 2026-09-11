"""Propagate register-address constants across the whole 0xC3F9_xxxx peripheral
page (SIUL 0xC3F90000 *and* WKPU 0xC3F94000) to settle whether the interior
LOCK/UNLOCK pads (PI15 / PF12) reach firmware via a wakeup/interrupt route.

Complements work/rke_gpio_raw.py (exact full-image 32-bit scan): that scan cannot
see a base formed as e_lis+e_add16i, which is exactly how a WKPU base would be
built. Read-only.
"""
import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from collections import defaultdict

PROJ = "/home/gl/Projects/ford/BCM/Research/ghidra_proj"
SIU = 0xC3F90000
WKPU = 0xC3F94000
PAGE_LO, PAGE_HI = 0xC3F90000, 0xC3F9FFFF

project = GhidraProject.openProject(PROJ, "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()

    def A(x):
        return af.getAddress(x)

    def fname(a):
        f = fm.getFunctionContaining(a)
        return f.getName() if f else "?"

    def rd32(addr):
        try:
            b = bytearray(4)
            mem.getBytes(A(addr), b)
            return int.from_bytes(bytes(b), "big")
        except Exception:
            return None

    LD = {"e_lbz", "e_lhz", "e_lwz", "lbz", "lhz", "lwz", "se_lwz", "se_lbz", "se_lhz"}
    ST = {"e_stb", "e_sth", "e_stw", "stb", "sth", "stw", "se_stw", "se_stb", "se_sth"}
    LSX = {"e_lbzx", "lbzx", "e_lhzx", "lhzx", "e_lwzx", "lwzx", "e_stbx", "stbx",
           "e_sthx", "sthx", "e_stwx", "stwx", "se_lwzx", "se_stwx"}
    LS = LD | ST

    def isreg(o):
        return o.__class__.__name__.endswith(".Register")

    def isscalar(o):
        return o.__class__.__name__.endswith(".Scalar")

    def opparse(ins):
        base, disp = None, 0
        for oi in range(ins.getNumOperands()):
            objs = list(ins.getOpObjects(oi))
            rs = [o for o in objs if isreg(o)]
            sc = [o for o in objs if isscalar(o)]
            if rs and sc:
                base = rs[0].getName()
                disp = sc[0].getSignedValue()
            elif rs and oi > 0 and base is None:
                base = rs[0].getName()
                disp = 0
        return base, disp

    hits = defaultdict(list)   # abs addr -> [(site, func, acc, mnem)]
    idxbase = []

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
                        val[rd.getName()] = (val[rd.getName()] | sc.getUnsignedValue()) & 0xFFFFFFFF
                elif mn in LSX:
                    regs = [ins.getRegister(k) for k in range(ins.getNumOperands())
                            if ins.getRegister(k)]
                    for r in regs:
                        b = val.get(r.getName())
                        if b is not None and PAGE_LO <= b <= PAGE_HI:
                            idxbase.append((str(ins.getAddress()), fname(ins.getAddress()),
                                            mn, r.getName(), b))
                elif mn in LS:
                    base, disp = opparse(ins)
                    if base in val:
                        ea = (val[base] + disp) & 0xFFFFFFFF
                        if PAGE_LO <= ea <= PAGE_HI:
                            hits[ea].append((str(ins.getAddress()), fname(ins.getAddress()),
                                             "ST" if mn in ST else "LD", mn))
                        if mn in LD:
                            rd = ins.getRegister(0)
                            w = rd32(ea)
                            if rd is not None:
                                if w is not None and (w >> 24) in (0xC3, 0xFF):
                                    val[rd.getName()] = w
                                else:
                                    val.pop(rd.getName(), None)
            except Exception:
                pass

    def decode(ea):
        if WKPU <= ea < WKPU + 0x1000:
            off = ea - WKPU
            named = {0x00: "NSR", 0x08: "NCR", 0x14: "WISR", 0x18: "IRER",
                     0x1C: "WRER", 0x28: "WIREER", 0x2C: "WIFEER", 0x30: "WIFER",
                     0x34: "WIPUER"}
            return "WKPU.%s" % named.get(off, "+0x%X" % off)
        off = ea - SIU
        if 0x40 <= off < 0x240 and off % 2 == 0:
            return "SIU.PCR[%d]" % ((off - 0x40) // 2)
        if 0x600 <= off < 0x700:
            return "SIU.GPDO[pad %d]" % (off - 0x600)
        if 0x800 <= off < 0x900:
            return "SIU.GPDI[pad %d]" % (off - 0x800)
        if 0xC00 <= off < 0xC40:
            return "SIU.PGPDO[port %d]" % ((off - 0xC00) // 2)
        if 0xC40 <= off < 0xC80:
            return "SIU.PGPDI[port %d]" % ((off - 0xC40) // 2)
        named = {0x0: "MIDR1", 0x4: "MIDR2", 0x14: "ISR(EIRQ)", 0x18: "IRER",
                 0x28: "IREER", 0x2C: "IFEER", 0x30: "IFER", 0x38: "IFMC"}
        return "SIU.%s" % named.get(off, "+0x%X" % off)

    TARGETS = {
        0xC3F9015E: "PI15 PCR[143]", 0xC3F9088F: "PI15 GPDI", 0xC3F9068F: "PI15 GPDO",
        0xC3F900F8: "PF12 PCR[92]", 0xC3F9085C: "PF12 GPDI", 0xC3F9065C: "PF12 GPDO",
    }

    print("=== accesses resolved into 0xC3F9_xxxx (SIUL + WKPU) ===")
    for ea in sorted(hits):
        lst = hits[ea]
        print("  0x%08X %-20s x%-3d e.g. %s [%s] %s %s"
              % (ea, decode(ea), len(lst), lst[0][0], lst[0][1], lst[0][2], lst[0][3]))

    wk = [ea for ea in hits if WKPU <= ea < WKPU + 0x1000]
    print("\n=== WKPU (0xC3F94000) accesses: %d ===" % len(wk))
    for ea in sorted(wk):
        for site, fn, acc, mn in hits[ea]:
            print("  0x%08X %-16s @%s [%s] %s %s" % (ea, decode(ea), site, fn, acc, mn))
    if not wk:
        print("  (none — WKPU peripheral is never touched by this firmware)")

    print("\n=== target pad registers (PI15 / PF12) ===")
    for ea, nm in sorted(TARGETS.items()):
        print("  0x%08X %-14s : %s" % (ea, nm, "FOUND %d" % len(hits[ea]) if ea in hits else "absent"))

    print("\n=== indexed load/store with base in page ===")
    for a, fn, mn, rn, b in idxbase:
        print("  @%s [%s] %s base %s=0x%08X (%s)" % (a, fn, mn, rn, b, decode(b)))
    if not idxbase:
        print("  (none)")
finally:
    project.close()
