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
    fm = program.getFunctionManager()
    # Find pointer CONSTANTS in data/code pointing into FlexCAN region 0xFFFC0000..0xFFFD0000
    # 1) scan defined data for pointer values
    mem = program.getMemory()
    # scan all 4-byte words in flash for 0xFFFC0000..0xFFFD0000
    import struct
    img = open("/home/gl/Projects/ford/BCM/Research/work/flash_merged.bin","rb").read()
    def u32(a): return struct.unpack_from(">I",img,a)[0]
    print("=== flash words pointing into 0xFFFC0000..0xFFFD0000 (FlexCAN) ===")
    cnt=0
    for a in range(0x10000, len(img)-4, 2):
        v=u32(a)
        if 0xFFFC0000 <= v < 0xFFFD0000:
            print("  @0x%06X -> 0x%08X"%(a,v)); cnt+=1
            if cnt>60: break
    print("total-ish:",cnt)
finally:
    project.close()
