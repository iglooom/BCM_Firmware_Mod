"""Enumerate WKPU wakeup-channel usage: callers of the per-channel enable helper
and the literal channel numbers they pass. Read-only."""
import os, sys, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject

PROJ = "/home/gl/Projects/ford/BCM/Research/ghidra_proj"
TARGETS = [int(a, 16) for a in (sys.argv[1:] or ["0x3592e"])]

project = GhidraProject.openProject(PROJ, "BCM_C1MCA", False)
program = project.openProgram("/", "flash_merged.bin", False)
try:
    listing = program.getListing()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    rm = program.getReferenceManager()

    def A(x):
        return af.getAddress(x)

    def fname(a):
        f = fm.getFunctionContaining(a)
        return f.getName() if f else "?"

    for tgt in TARGETS:
        ta = A(tgt)
        print("\n===== callers of FUN_%08x =====" % tgt)
        refs = list(rm.getReferencesTo(ta))
        if not refs:
            print("  (no resolved references)")
        for r in refs:
            site = r.getFromAddress()
            fn = fm.getFunctionContaining(site)
            print("\n  call @%s in [%s] (%s)" % (site, fname(site), r.getReferenceType()))
            if fn is None:
                continue
            # back-walk up to 24 instructions looking for the r3 (first arg) load
            ins = listing.getInstructionAt(site)
            hist = []
            cur = ins
            for _ in range(24):
                cur = cur.getPrevious()
                if cur is None or not fn.getBody().contains(cur.getAddress()):
                    break
                hist.append(cur)
            for cur in hist:
                mn = cur.getMnemonicString()
                rd = cur.getRegister(0)
                if rd is not None and rd.getName() in ("r3", "r0") and \
                   mn in ("e_li", "li", "se_li", "e_lis", "e_add16i", "e_addi",
                          "se_mtar", "se_mr", "e_lbz", "e_lwz"):
                    print("      arg-setup @%s  %s" % (cur.getAddress(), cur))
                    if rd.getName() == "r3":
                        break
finally:
    project.close()
