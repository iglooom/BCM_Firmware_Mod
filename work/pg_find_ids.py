"""Open the existing BCM project headless via pyghidra and find CAN-ID code refs."""
import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.program.model.scalar import Scalar

PROJ_DIR = "/home/gl/Projects/ford/BCM/Research/ghidra_proj"
PROJ_NAME = "BCM_C1MCA"

project = GhidraProject.openProject(PROJ_DIR, PROJ_NAME, False)
program = project.openProgram("/", "flash_merged.bin", False)

try:
    fm = program.getFunctionManager()
    listing = program.getListing()
    print("FUNCTION COUNT:", fm.getFunctionCount())

    targets = {
        0x03000000: "0x0C0<<18 (HS RX std)",
        0x01800000: "0x060<<18 (HS RX std)",
        0x00800000: "0x020<<18 (MS TX std)",
        0x0C0: "0x0C0 raw",
        0x060: "0x060 raw",
        0x020: "0x020 raw",
        0x18: "0x0C0>>3? ", # placeholder
    }
    hits = {}
    n = 0
    for ins in listing.getInstructions(True):
        n += 1
        for oi in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(oi):
                if isinstance(obj, Scalar):
                    v = obj.getUnsignedValue() & 0xFFFFFFFF
                    if v in targets:
                        f = fm.getFunctionContaining(ins.getAddress())
                        fn = (f.getName()+"@"+str(f.getEntryPoint())) if f else "(none)"
                        hits.setdefault(v, []).append((str(ins.getAddress()), fn, str(ins)))
    print("instructions scanned:", n)
    for t, lbl in targets.items():
        lst = hits.get(t, [])
        print("\n--- %s (0x%X): %d code hits ---" % (lbl, t, len(lst)))
        for a, fn, txt in lst[:30]:
            print("   %s  %-38s  %s" % (a, fn, txt))
finally:
    project.close()
