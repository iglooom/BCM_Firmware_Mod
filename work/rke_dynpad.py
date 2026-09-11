"""Find OUTPUT-driving code that dynamic addressing hides.

Two blind spots remain after the literal scan:
  (a) a generic pad-config driver computing  SIU + 0x40 + pad*2  (PCR) or
      SIU + 0x600 + pad (GPDO) at runtime -> no literal, no static base.
  (b) an eMIOS channel driver computing  base + 0x20 + ch*0x20   -> the 14
      indexed accesses seen on eMIOS_0. eMIOS = PWM = the usual MOSFET-gate
      driver, so this is the prime "output pin" candidate.

Strategy: don't try to resolve the arithmetic. Instead enumerate EVERY function
that materialises the SIUL page (e_lis rX,0xC3F9) or an eMIOS base, print the
instruction window, and let the multiply/shift pattern identify the driver.

Read-only.
"""
import os
import pyghidra

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

ROOT = "/home/gl/Projects/ford/BCM/Research"
project = GhidraProject.openProject(ROOT + "/ghidra_proj", "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()

    PAGES = {0xC3F9: "SIUL/WKPU", 0xC3FA: "eMIOS"}
    sites = []
    for f in fm.getFunctions(True):
        for ins in listing.getInstructions(f.getBody(), True):
            if ins.getMnemonicString() not in ("e_lis", "lis"):
                continue
            sc = ins.getScalar(1)
            rd = ins.getRegister(0)
            if sc is None or rd is None:
                continue
            hi = sc.getUnsignedValue() & 0xFFFF
            if hi in PAGES:
                sites.append((f.getName(), str(ins.getAddress()),
                              rd.getName(), hi, ins))

    print("=" * 78)
    print("functions materialising a SIUL / eMIOS page base: %d sites" % len(sites))
    print("=" * 78)
    byfunc = {}
    for fn, addr, reg, hi, ins in sites:
        byfunc.setdefault((fn, PAGES[hi]), []).append(addr)
    for (fn, pg), addrs in sorted(byfunc.items()):
        print("  %-22s %-10s x%d  (%s)" % (fn, pg, len(addrs), addrs[0]))

    # windows around each site, looking for index arithmetic
    IDX = ("e_slwi", "se_slwi", "slwi", "rlwinm", "mulli", "e_mulli",
           "add", "se_add", "e_add16i", "se_addi", "sthx", "stbx", "stwx",
           "lhzx", "lbzx", "lwzx")
    print("\n" + "=" * 78)
    print("instruction windows (looking for base + index*stride patterns)")
    print("=" * 78)
    for fn, addr, reg, hi, ins in sites:
        win, cur = [], ins
        for _ in range(12):
            nxt = cur.getNext()
            if nxt is None:
                break
            win.append(nxt)
            cur = nxt
        interesting = [w for w in win if w.getMnemonicString() in IDX]
        if not interesting:
            continue
        print("\n  -- %s @%s  (r%s = 0x%04X0000, %s)"
              % (fn, addr, reg, hi, PAGES[hi]))
        print("     %s  %s" % (ins.getAddress(), ins))
        for w in win:
            mark = "  <<" if w.getMnemonicString() in IDX else ""
            print("     %s  %s%s" % (w.getAddress(), w, mark))
finally:
    project.close()
