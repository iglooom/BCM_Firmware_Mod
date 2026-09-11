"""Identify the OS/scheduler and confirm the 0x104.. values are INTC vector
indices, not pointers into un-flashed low flash.

Checks:
  [1] INTC configuration (0xFFF48000): IACKR (vector table base) and how vectors
      are formed. If the table base points into the APP, the 0x104.. values are
      vector NUMBERS/offsets, not code addresses in low flash.
  [2] OS identification: OSEK/AUTOSAR/FreeRTOS/proprietary - by string scan and
      by the shape of the startup (task table, scheduler entry).
  [3] The startup calls from reset_entry, named.

Read-only.
"""
import os
import re
import struct
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
raw = open(ROOT + "/work/flash_merged.bin", "rb").read()

# ---------- [2] OS / RTOS strings ---------------------------------------
print("=" * 78)
print("[2] OS / RTOS / toolchain identification (ASCII strings)")
print("=" * 78)
PATTERNS = [
    rb"OSEK", rb"osek", rb"AUTOSAR", rb"Autosar", rb"autosar",
    rb"FreeRTOS", rb"freertos", rb"uCOS", rb"ucos", rb"MicroC",
    rb"Vector", rb"VECTOR", rb"MICROSAR", rb"OSCAN", rb"osCAN",
    rb"ERCOSEK", rb"ErcosEK", rb"RTA-OS", rb"Tresos", rb"EB tresos",
    rb"Task", rb"Scheduler", rb"SchM", rb"Rte_", rb"Dem_", rb"Dcm_",
    rb"CanIf", rb"ComM", rb"EcuM", rb"BswM", rb"Os_",
    rb"Diab", rb"WindRiver", rb"GreenHills", rb"CodeWarrior", rb"GHS",
    rb"Ford", rb"FORD", rb"Visteon", rb"Continental",
]
found = {}
for pat in PATTERNS:
    for m in re.finditer(re.escape(pat), raw):
        found.setdefault(pat.decode("latin1"), []).append(m.start())
for k in sorted(found):
    offs = found[k]
    print("  %-14s x%-4d e.g. %s" % (k, len(offs),
          ",".join(hex(o) for o in offs[:4])))
if not found:
    print("  (none)")

print("\n  -- printable strings near the app start (toolchain/banner) --")
for m in re.finditer(rb"[ -~]{8,}", raw[0xC000:0x14000]):
    s = m.group().decode("latin1")
    if any(c.isalpha() for c in s):
        print("     0x%06X  %s" % (0xC000 + m.start(), s[:90]))

project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    # ---------- [1] INTC vector table base ------------------------------
    print("\n" + "=" * 78)
    print("[1] INTC (0xFFF48000) accesses - vector table base / mode")
    print("=" * 78)
    INTC = 0xFFF48000
    REG = {0x00: "BCR (MCR)", 0x08: "CPR", 0x10: "IACKR", 0x18: "EOIR",
           0x40: "PSR base"}
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
                        if INTC <= ea < INTC + 0x4000:
                            sv = None
                            if mn in ST:
                                rs = ins.getRegister(0)
                                if rs is not None:
                                    sv = val.get(rs.getName())
                            print("    @%s [%s] %-8s INTC+0x%03X %-10s%s"
                                  % (ins.getAddress(), f.getName(), mn, ea - INTC,
                                     REG.get(ea - INTC, ""),
                                     "  value=0x%08X" % sv if sv is not None else ""))
            except Exception:
                pass

    # ---------- [3] startup calls ---------------------------------------
    print("\n" + "=" * 78)
    print("[3] functions called from reset_entry")
    print("=" * 78)
    for tgt in (0x10F570, 0x2FDF2, 0x2FEC8, 0x2FF70, 0x2F12E):
        a = af.getAddress(tgt)
        f = fm.getFunctionContaining(a)
        nm = f.getName() if f else "?"
        sz = f.getBody().getNumAddresses() if f else 0
        print("    0x%06X  %-22s (%d bytes)" % (tgt, nm, sz))
finally:
    project.close()
