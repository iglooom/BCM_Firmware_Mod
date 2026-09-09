import os, pyghidra
os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()
from ghidra.base.project import GhidraProject
from ghidra.program.model.scalar import Scalar
import collections

project = GhidraProject.openProject("/home/gl/Projects/ford/BCM/Research/ghidra_proj","BCM_C1MCA",False)
program = project.openProgram("/","flash_merged.bin",False)
try:
    listing = program.getListing()
    # histogram of high addresses referenced as scalars (peripheral bases)
    hi = collections.Counter()
    for ins in listing.getInstructions(True):
        for oi in range(ins.getNumOperands()):
            for obj in ins.getOpObjects(oi):
                if isinstance(obj, Scalar):
                    v = obj.getUnsignedValue() & 0xFFFFFFFF
                    if v >= 0xC3F00000 or (0xFFE00000 <= v <= 0xFFFFFFFF) or (0xFFF00000<=v<=0xFFFFFFFF):
                        hi[v>>12] += 1  # by 4K page
    print("=== top peripheral 4K pages referenced (page<<12 = base) ===")
    for page,cnt in hi.most_common(40):
        print("  0x%08X : %d" % (page<<12, cnt))
finally:
    project.close()
